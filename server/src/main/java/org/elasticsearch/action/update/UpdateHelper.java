/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.action.update;

import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.DocWriteResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.index.get.GetResult;
import org.elasticsearch.index.mapper.RoutingFieldMapper;
import org.elasticsearch.index.shard.IndexShard;
import org.elasticsearch.search.lookup.Source;
import org.elasticsearch.xcontent.XContentType;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.function.LongSupplier;

public interface UpdateHelper {

    UpdateHelper.Result prepare(UpdateRequest request, IndexShard indexShard, LongSupplier nowInMillis) throws IOException;

    /**
     * Applies {@link UpdateRequest#fetchSource()} to the _source of the updated document to be returned in a update response.
     * // TODO can we pass a Source here rather than Map, XcontentType and BytesReference?
     */
    static GetResult extractGetResult(
        final UpdateRequest request,
        String concreteIndex,
        long seqNo,
        long primaryTerm,
        long version,
        final Map<String, Object> source,
        XContentType sourceContentType,
        @Nullable final BytesReference sourceAsBytes
    ) {
        if (request.fetchSource() == null || request.fetchSource().fetchSource() == false) {
            return null;
        }
        BytesReference sourceFilteredAsBytes = sourceAsBytes;
        if (request.fetchSource().hasFilter()) {
            sourceFilteredAsBytes = Source.fromMap(source, sourceContentType).filter(request.fetchSource().filter()).internalSourceRef();
        }

        // TODO when using delete/none, we can still return the source as bytes by generating it (using the sourceContentType)
        return new GetResult(
            concreteIndex,
            request.id(),
            seqNo,
            primaryTerm,
            version,
            true,
            sourceFilteredAsBytes,
            Collections.emptyMap(),
            Collections.emptyMap()
        );
    }

    /**
     * Calculate a routing value to be used, either the included index request's routing, or retrieved document's routing when defined.
     */
    @Nullable
    static String calculateRouting(GetResult getResult, @Nullable IndexRequest updateIndexRequest) {
        if (updateIndexRequest != null && updateIndexRequest.routing() != null) {
            return updateIndexRequest.routing();
        } else if (getResult.getFields().containsKey(RoutingFieldMapper.NAME)) {
            return getResult.field(RoutingFieldMapper.NAME).getValue().toString();
        } else {
            return null;
        }
    }

    /**
     * After executing the script, this is the type of operation that will be used for subsequent actions. This corresponds to the "ctx.op"
     * variable inside of scripts.
     */
    enum UpdateOpType {
        CREATE("create"),
        INDEX("index"),
        DELETE("delete"),
        NONE("none");

        private final String name;

        UpdateOpType(String name) {
            this.name = name;
        }

        public static UpdateOpType lenientFromString(String operation, Logger logger, String scriptId) {
            switch (operation) {
                case "create":
                    return UpdateOpType.CREATE;
                case "index":
                    return UpdateOpType.INDEX;
                case "delete":
                    return UpdateOpType.DELETE;
                case "noop":
                case "none":
                    return UpdateOpType.NONE;
                default:
                    // TODO: can we remove this leniency yet??
                    logger.warn("Used upsert operation [{}] for script [{}], doing nothing...", operation, scriptId);
                    return UpdateOpType.NONE;
            }
        }

        @Override
        public String toString() {
            return name;
        }
    }

    class Result {

        private final Writeable action;
        private final DocWriteResponse.Result result;
        private final Map<String, Object> updatedSourceAsMap;
        private final XContentType updateSourceContentType;

        public Result(
            Writeable action,
            DocWriteResponse.Result result,
            Map<String, Object> updatedSourceAsMap,
            XContentType updateSourceContentType
        ) {
            this.action = action;
            this.result = result;
            this.updatedSourceAsMap = updatedSourceAsMap;
            this.updateSourceContentType = updateSourceContentType;
        }

        @SuppressWarnings("unchecked")
        public <T extends Writeable> T action() {
            return (T) action;
        }

        public DocWriteResponse.Result getResponseResult() {
            return result;
        }

        public Map<String, Object> updatedSourceAsMap() {
            return updatedSourceAsMap;
        }

        public XContentType updateSourceContentType() {
            return updateSourceContentType;
        }
    }

    /**
     * Field names used to populate the script context
     */
    class ContextFields {
        public static final String CTX = "ctx";
        public static final String OP = "op";
        public static final String SOURCE = "_source";
        public static final String NOW = "_now";
        public static final String INDEX = "_index";
        public static final String TYPE = "_type";
        public static final String ID = "_id";
        public static final String VERSION = "_version";
        public static final String ROUTING = "_routing";
    }
}
