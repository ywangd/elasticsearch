/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.action.update;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.DocWriteResponse;
import org.elasticsearch.action.delete.DeleteRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.internal.Requests;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.index.VersionType;
import org.elasticsearch.index.engine.DocumentMissingException;
import org.elasticsearch.index.engine.DocumentSourceMissingException;
import org.elasticsearch.index.get.GetResult;
import org.elasticsearch.index.mapper.MapperService;
import org.elasticsearch.index.shard.IndexShard;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.script.Script;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.script.UpdateCtxMap;
import org.elasticsearch.script.UpdateScript;
import org.elasticsearch.script.UpsertCtxMap;
import org.elasticsearch.xcontent.XContentType;

import java.io.IOException;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * Helper for translating an update request to an index, delete request or update response.
 */
public class DefaultUpdateHelper implements UpdateHelper {

    private static final Logger logger = LogManager.getLogger(DefaultUpdateHelper.class);

    private final ScriptService scriptService;

    public DefaultUpdateHelper(ScriptService scriptService) {
        this.scriptService = scriptService;
    }

    /**
     * Prepares an update request by converting it into an index or delete request or an update response (no action).
     */
    @Override
    public Result prepare(UpdateRequest request, IndexShard indexShard, LongSupplier nowInMillis) throws IOException {
        final GetResult getResult = indexShard.getService().getForUpdate(request.id(), request.ifSeqNo(), request.ifPrimaryTerm());
        return prepare(indexShard.shardId(), request, getResult, nowInMillis, indexShard);
    }

    /**
     * Prepares an update request by converting it into an index or delete request or an update response (no action, in the event of a
     * noop).
     */
    protected Result prepare(
        ShardId shardId,
        UpdateRequest request,
        final GetResult getResult,
        LongSupplier nowInMillis,
        IndexShard indexShard
    ) {
        if (getResult.isExists() == false) {
            // If the document didn't exist, execute the update request as an upsert
            return prepareUpsert(shardId, request, getResult, nowInMillis);
        } else if (getResult.internalSourceRef() == null) {
            // no source, we can't do anything, throw a failure...
            throw new DocumentSourceMissingException(shardId, request.id());
        } else if (request.script() == null && request.doc() != null) {
            // The request has no script, it is a new doc that should be merged with the old document
            return prepareUpdateIndexRequest(shardId, request, getResult, request.detectNoop(), indexShard);
        } else {
            // The request has a script (or empty script), execute the script and prepare a new index request
            return prepareUpdateScriptRequest(shardId, request, getResult, nowInMillis, indexShard);
        }
    }

    protected Map<String, Object> validateAndTransform(
        Map<String, Object> source,
        IndexShard indexShard,
        String id,
        long primaryTerm,
        long seqNo
    ) {
        return source;
    }

    /**
     * Execute a scripted upsert, where there is an existing upsert document and a script to be executed. The script is executed and a new
     * Tuple of operation and updated {@code _source} is returned.
     */
    Tuple<UpdateOpType, Map<String, Object>> executeScriptedUpsert(Script script, UpsertCtxMap ctxMap) {
        ctxMap = executeScript(script, ctxMap);
        UpdateOpType operation = UpdateOpType.lenientFromString(ctxMap.getMetadata().getOp(), logger, script.getIdOrCode());
        if (operation != UpdateOpType.CREATE && operation != UpdateOpType.NONE) {
            // Only valid options for an upsert script are "create" (the default) or "none", meaning abort upsert
            logger.warn("Invalid upsert operation [{}] for script [{}], doing nothing...", operation, script.getIdOrCode());
            operation = UpdateOpType.NONE;
        }

        return new Tuple<>(operation, ctxMap.getSource());
    }

    /**
     * Prepare the request for upsert, executing the upsert script if present, and returning a {@code Result} containing a new
     * {@code IndexRequest} to be executed on the primary and replicas.
     */
    Result prepareUpsert(ShardId shardId, UpdateRequest request, final GetResult getResult, LongSupplier nowInMillis) {
        if (request.upsertRequest() == null && request.docAsUpsert() == false) {
            throw new DocumentMissingException(shardId, request.id());
        }
        IndexRequest indexRequest = request.docAsUpsert() ? request.doc() : request.upsertRequest();
        if (request.scriptedUpsert() && request.script() != null) {
            // Run the script to perform the create logic
            IndexRequest upsert = request.upsertRequest();
            UpsertCtxMap ctxMap = new UpsertCtxMap(
                getResult.getIndex(),
                getResult.getId(),
                UpdateOpType.CREATE.toString(),
                nowInMillis.getAsLong(),
                upsert.sourceAsMap()
            );
            Tuple<UpdateOpType, Map<String, Object>> upsertResult = executeScriptedUpsert(request.script, ctxMap);
            switch (upsertResult.v1()) {
                case CREATE -> indexRequest = Requests.indexRequest(request.index()).source(upsertResult.v2());
                case NONE -> {
                    UpdateResponse update = new UpdateResponse(
                        shardId,
                        getResult.getId(),
                        getResult.getSeqNo(),
                        getResult.getPrimaryTerm(),
                        getResult.getVersion(),
                        DocWriteResponse.Result.NOOP
                    );
                    update.setGetResult(getResult);
                    return new Result(update, DocWriteResponse.Result.NOOP, upsertResult.v2(), XContentType.JSON);
                }
                default ->
                    // It's fine to throw an exception here, the leniency is handled/logged by `executeScriptedUpsert`
                    throw new IllegalArgumentException("unknown upsert operation, got: " + upsertResult.v1());
            }
        }

        indexRequest.index(request.index())
            .id(request.id())
            .setRefreshPolicy(request.getRefreshPolicy())
            .routing(request.routing())
            .timeout(request.timeout())
            .waitForActiveShards(request.waitForActiveShards())
            // it has to be a "create!"
            .create(true);

        if (request.versionType() != VersionType.INTERNAL) {
            // in all but the internal versioning mode, we want to create the new document using the given version.
            indexRequest.version(request.version()).versionType(request.versionType());
        }

        return new Result(indexRequest, DocWriteResponse.Result.CREATED, null, null);
    }

    /**
     * Prepare the request for merging the existing document with a new one, can optionally detect a noop change. Returns a {@code Result}
     * containing a new {@code IndexRequest} to be executed on the primary and replicas.
     */
    Result prepareUpdateIndexRequest(
        ShardId shardId,
        UpdateRequest request,
        GetResult getResult,
        boolean detectNoop,
        IndexShard indexShard
    ) {
        final IndexRequest currentRequest = request.doc();
        final String routing = UpdateHelper.calculateRouting(getResult, currentRequest);
        final Tuple<XContentType, Map<String, Object>> sourceAndContent = XContentHelper.convertToMap(getResult.internalSourceRef(), true);
        final XContentType updateSourceContentType = sourceAndContent.v1();
        final Map<String, Object> updatedSourceAsMap = sourceAndContent.v2();

        final boolean noop = XContentHelper.update(updatedSourceAsMap, currentRequest.sourceAsMap(), detectNoop) == false;

        // We can only actually turn the update into a noop if detectNoop is true to preserve backwards compatibility and to handle cases
        // where users repopulating multi-fields or adding synonyms, etc.
        if (detectNoop && noop) {
            UpdateResponse update = new UpdateResponse(
                shardId,
                getResult.getId(),
                getResult.getSeqNo(),
                getResult.getPrimaryTerm(),
                getResult.getVersion(),
                DocWriteResponse.Result.NOOP
            );
            update.setGetResult(
                UpdateHelper.extractGetResult(
                    request,
                    request.index(),
                    getResult.getSeqNo(),
                    getResult.getPrimaryTerm(),
                    getResult.getVersion(),
                    updatedSourceAsMap,
                    updateSourceContentType,
                    getResult.internalSourceRef()
                )
            );
            return new Result(update, DocWriteResponse.Result.NOOP, updatedSourceAsMap, updateSourceContentType);
        } else {
            final IndexRequest finalIndexRequest = Requests.indexRequest(request.index())
                .id(request.id())
                .routing(routing)
                .source(
                    validateAndTransform(
                        updatedSourceAsMap,
                        indexShard,
                        getResult.getId(),
                        getResult.getPrimaryTerm(),
                        getResult.getSeqNo()
                    ),
                    updateSourceContentType
                )
                .setIfSeqNo(getResult.getSeqNo())
                .setIfPrimaryTerm(getResult.getPrimaryTerm())
                .waitForActiveShards(request.waitForActiveShards())
                .timeout(request.timeout())
                .setRefreshPolicy(request.getRefreshPolicy());
            return new Result(finalIndexRequest, DocWriteResponse.Result.UPDATED, updatedSourceAsMap, updateSourceContentType);
        }
    }

    /**
     * Prepare the request for updating an existing document using a script. Executes the script and returns a {@code Result} containing
     * either a new {@code IndexRequest} or {@code DeleteRequest} (depending on the script's returned "op" value) to be executed on the
     * primary and replicas.
     */
    Result prepareUpdateScriptRequest(
        ShardId shardId,
        UpdateRequest request,
        GetResult getResult,
        LongSupplier nowInMillis,
        IndexShard indexShard
    ) {
        final IndexRequest currentRequest = request.doc();
        final String routing = UpdateHelper.calculateRouting(getResult, currentRequest);
        final Tuple<XContentType, Map<String, Object>> sourceAndContent = XContentHelper.convertToMap(getResult.internalSourceRef(), true);
        final XContentType updateSourceContentType = sourceAndContent.v1();

        UpdateCtxMap ctxMap = executeScript(
            request.script,
            new UpdateCtxMap(
                getResult.getIndex(),
                getResult.getId(),
                getResult.getVersion(),
                routing,
                MapperService.SINGLE_MAPPING_NAME,
                UpdateOpType.INDEX.toString(), // The default operation is "index"
                nowInMillis.getAsLong(),
                sourceAndContent.v2()
            )
        );
        UpdateOpType operation = UpdateOpType.lenientFromString(ctxMap.getMetadata().getOp(), logger, request.script.getIdOrCode());
        final Map<String, Object> updatedSourceAsMap = ctxMap.getSource();

        switch (operation) {
            case INDEX -> {
                final IndexRequest indexRequest = Requests.indexRequest(request.index())
                    .id(request.id())
                    .routing(routing)
                    .source(
                        validateAndTransform(
                            updatedSourceAsMap,
                            indexShard,
                            getResult.getId(),
                            getResult.getPrimaryTerm(),
                            getResult.getSeqNo()
                        ),
                        updateSourceContentType
                    )
                    .setIfSeqNo(getResult.getSeqNo())
                    .setIfPrimaryTerm(getResult.getPrimaryTerm())
                    .waitForActiveShards(request.waitForActiveShards())
                    .timeout(request.timeout())
                    .setRefreshPolicy(request.getRefreshPolicy());
                return new Result(indexRequest, DocWriteResponse.Result.UPDATED, updatedSourceAsMap, updateSourceContentType);
            }
            case DELETE -> {
                DeleteRequest deleteRequest = Requests.deleteRequest(request.index())
                    .id(request.id())
                    .routing(routing)
                    .setIfSeqNo(getResult.getSeqNo())
                    .setIfPrimaryTerm(getResult.getPrimaryTerm())
                    .waitForActiveShards(request.waitForActiveShards())
                    .timeout(request.timeout())
                    .setRefreshPolicy(request.getRefreshPolicy());
                return new Result(deleteRequest, DocWriteResponse.Result.DELETED, updatedSourceAsMap, updateSourceContentType);
            }
            default -> {
                // If it was neither an INDEX or DELETE operation, treat it as a noop
                UpdateResponse update = new UpdateResponse(
                    shardId,
                    getResult.getId(),
                    getResult.getSeqNo(),
                    getResult.getPrimaryTerm(),
                    getResult.getVersion(),
                    DocWriteResponse.Result.NOOP
                );
                update.setGetResult(
                    UpdateHelper.extractGetResult(
                        request,
                        request.index(),
                        getResult.getSeqNo(),
                        getResult.getPrimaryTerm(),
                        getResult.getVersion(),
                        updatedSourceAsMap,
                        updateSourceContentType,
                        getResult.internalSourceRef()
                    )
                );
                return new Result(update, DocWriteResponse.Result.NOOP, updatedSourceAsMap, updateSourceContentType);
            }
        }
    }

    private <T extends UpdateCtxMap> T executeScript(Script script, T ctxMap) {
        try {
            if (scriptService != null) {
                UpdateScript.Factory factory = scriptService.compile(script, UpdateScript.CONTEXT);
                UpdateScript executableScript = factory.newInstance(script.getParams(), ctxMap);
                executableScript.execute();
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("failed to execute script", e);
        }
        return ctxMap;
    }

}
