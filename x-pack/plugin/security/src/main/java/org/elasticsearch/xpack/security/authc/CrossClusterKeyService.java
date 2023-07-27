/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.ResourceNotFoundException;
import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRunnable;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.DocWriteResponse;
import org.elasticsearch.action.bulk.BulkAction;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.bulk.TransportBulkAction;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.ContextPreservingActionListener;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.action.update.UpdateResponse;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.UUIDs;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.cache.Cache;
import org.elasticsearch.common.cache.CacheBuilder;
import org.elasticsearch.common.hash.MessageDigests;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.EsRejectedExecutionException;
import org.elasticsearch.common.util.concurrent.ListenableFuture;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.ObjectParserHelper;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.core.CharArrays;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xcontent.InstantiatingObjectParser;
import org.elasticsearch.xcontent.ParseField;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xcontent.XContentFactory;
import org.elasticsearch.xcontent.XContentParser;
import org.elasticsearch.xcontent.XContentParserConfiguration;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.core.XPackSettings;
import org.elasticsearch.xpack.core.security.ScrollHelper;
import org.elasticsearch.xpack.core.security.action.ClearSecurityCacheAction;
import org.elasticsearch.xpack.core.security.action.ClearSecurityCacheRequest;
import org.elasticsearch.xpack.core.security.action.ClearSecurityCacheResponse;
import org.elasticsearch.xpack.core.security.action.apikey.AbstractCreateApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.apikey.ApiKey;
import org.elasticsearch.xpack.core.security.action.apikey.BaseBulkUpdateApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.apikey.BaseUpdateApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.apikey.BulkUpdateApiKeyResponse;
import org.elasticsearch.xpack.core.security.action.apikey.CreateCrossClusterKeyResponse;
import org.elasticsearch.xpack.core.security.action.apikey.CrossClusterKey;
import org.elasticsearch.xpack.core.security.action.apikey.GetCrossClusterKeyResponse;
import org.elasticsearch.xpack.core.security.action.apikey.InvalidateApiKeyResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.AuthenticationField;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.authc.support.Hasher;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.user.User;
import org.elasticsearch.xpack.security.support.CacheInvalidatorRegistry;
import org.elasticsearch.xpack.security.support.LockingAtomicCounter;
import org.elasticsearch.xpack.security.support.SecurityIndexManager;

import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.elasticsearch.core.Strings.format;
import static org.elasticsearch.search.SearchService.DEFAULT_KEEPALIVE_SETTING;
import static org.elasticsearch.xcontent.ConstructingObjectParser.constructorArg;
import static org.elasticsearch.xcontent.ConstructingObjectParser.optionalConstructorArg;
import static org.elasticsearch.xpack.core.ClientHelper.SECURITY_ORIGIN;
import static org.elasticsearch.xpack.core.ClientHelper.executeAsyncWithOrigin;
import static org.elasticsearch.xpack.security.Security.SECURITY_CRYPTO_THREAD_POOL_NAME;
import static org.elasticsearch.xpack.security.support.SecuritySystemIndices.SECURITY_MAIN_ALIAS;

public class CrossClusterKeyService {

    private static final Logger logger = LogManager.getLogger(CrossClusterKeyService.class);

    public static final Setting<String> PASSWORD_HASHING_ALGORITHM = XPackSettings.defaultStoredHashAlgorithmSetting(
        "xpack.security.authc.cross_cluster.hashing.algorithm",
        (s) -> Hasher.PBKDF2.name()
    );
    public static final Setting<String> CACHE_HASH_ALGO_SETTING = Setting.simpleString(
        "xpack.security.authc.cross_cluster.cache.hash_algo",
        "ssha256",
        Property.NodeScope
    );
    public static final Setting<TimeValue> CACHE_TTL_SETTING = Setting.timeSetting(
        "xpack.security.authc.cross_cluster.cache.ttl",
        TimeValue.timeValueHours(24L),
        Property.NodeScope
    );
    public static final Setting<Integer> CACHE_MAX_KEYS_SETTING = Setting.intSetting(
        "xpack.security.authc.cross_cluster.cache.max_keys",
        25000,
        Property.NodeScope
    );
    public static final Setting<TimeValue> DOC_CACHE_TTL_SETTING = Setting.timeSetting(
        "xpack.security.authc.cross_cluster.doc_cache.ttl",
        TimeValue.timeValueMinutes(5),
        TimeValue.timeValueMinutes(0),
        TimeValue.timeValueMinutes(15),
        Property.NodeScope
    );

    private final Client client;
    private final SecurityIndexManager securityIndex;
    private final ClusterService clusterService;
    private final Hasher hasher;
    private final Settings settings;
    private final Cache<String, ListenableFuture<CachedCrossClusterKeyHashResult>> authCache;
    private final Hasher cacheHasher;
    private final ThreadPool threadPool;
    private final DocCache docCache;

    public CrossClusterKeyService(
        Settings settings,
        Client client,
        SecurityIndexManager securityIndex,
        ClusterService clusterService,
        CacheInvalidatorRegistry cacheInvalidatorRegistry,
        ThreadPool threadPool
    ) {
        this.client = client;
        this.securityIndex = securityIndex;
        this.clusterService = clusterService;
        this.hasher = Hasher.resolve(PASSWORD_HASHING_ALGORITHM.get(settings));
        this.settings = settings;
        this.threadPool = threadPool;
        this.cacheHasher = Hasher.resolve(CACHE_HASH_ALGO_SETTING.get(settings));
        final TimeValue ttl = CACHE_TTL_SETTING.get(settings);
        final int maximumWeight = CACHE_MAX_KEYS_SETTING.get(settings);
        if (ttl.getNanos() > 0) {
            this.authCache = CacheBuilder.<String, ListenableFuture<CachedCrossClusterKeyHashResult>>builder()
                .setExpireAfterAccess(ttl)
                .setMaximumWeight(maximumWeight)
                .build();
            final TimeValue doc_ttl = DOC_CACHE_TTL_SETTING.get(settings);
            this.docCache = doc_ttl.getNanos() == 0 ? null : new DocCache(doc_ttl, maximumWeight);
            cacheInvalidatorRegistry.registerCacheInvalidator("cross_cluster_key", new CacheInvalidatorRegistry.CacheInvalidator() {
                @Override
                public void invalidate(Collection<String> keys) {
                    if (docCache != null) {
                        docCache.invalidate(keys);
                    }
                    keys.forEach(authCache::invalidate);
                }

                @Override
                public void invalidateAll() {
                    if (docCache != null) {
                        docCache.invalidateAll();
                    }
                    authCache.invalidateAll();
                }
            });
            cacheInvalidatorRegistry.registerCacheInvalidator("cross_cluster_key_doc", new CacheInvalidatorRegistry.CacheInvalidator() {
                @Override
                public void invalidate(Collection<String> keys) {
                    if (docCache != null) {
                        docCache.invalidate(keys);
                    }
                }

                @Override
                public void invalidateAll() {
                    if (docCache != null) {
                        docCache.invalidateAll();
                    }
                }
            });
        } else {
            this.authCache = null;
            this.docCache = null;
        }
    }

    /**
     * Asynchronously creates a new cross cluster key based off of the request and authentication
     * @param authentication the authentication that this cross cluster key should be based off of
     * @param request the request to create the cross cluster key included any permission restrictions
     * @param listener the listener that will be used to notify of completion
     */
    public void createCrossClusterKey(
        Authentication authentication,
        AbstractCreateApiKeyRequest request,
        ActionListener<CreateCrossClusterKeyResponse> listener
    ) {
        createCrossClusterKeyAndIndexIt(request, listener);
    }

    private void createCrossClusterKeyAndIndexIt(
        AbstractCreateApiKeyRequest request,
        ActionListener<CreateCrossClusterKeyResponse> listener
    ) {
        final SecureString secret = UUIDs.randomBase64UUIDSecureString();
        final Version version = clusterService.state().nodes().getMinNodeVersion();
        computeHashForSecret(secret, listener.delegateFailure((l, secretHashChars) -> {
            try (XContentBuilder builder = newDocument(secretHashChars, request.getName(), request.getRoleDescriptors(), version)) {
                final BulkRequestBuilder bulkRequestBuilder = client.prepareBulk();
                bulkRequestBuilder.add(
                    client.prepareIndex(SECURITY_MAIN_ALIAS)
                        .setSource(builder)
                        .setId(keyIdToDocId(request.getId()))
                        .setOpType(DocWriteRequest.OpType.CREATE)
                        .request()
                );
                bulkRequestBuilder.setRefreshPolicy(request.getRefreshPolicy());
                final BulkRequest bulkRequest = bulkRequestBuilder.request();

                securityIndex.prepareIndexIfNeededThenExecute(
                    listener::onFailure,
                    () -> executeAsyncWithOrigin(
                        client,
                        SECURITY_ORIGIN,
                        BulkAction.INSTANCE,
                        bulkRequest,
                        TransportBulkAction.<IndexResponse>unwrappingSingleItemBulkResponse(ActionListener.wrap(indexResponse -> {
                            assert keyIdToDocId(request.getId()).equals(indexResponse.getId());
                            assert indexResponse.getResult() == DocWriteResponse.Result.CREATED;
                            final ListenableFuture<CachedCrossClusterKeyHashResult> listenableFuture = new ListenableFuture<>();
                            listenableFuture.onResponse(new CachedCrossClusterKeyHashResult(true, secret));
                            authCache.put(request.getId(), listenableFuture);
                            listener.onResponse(new CreateCrossClusterKeyResponse(request.getName(), request.getId(), secret));
                        }, listener::onFailure))
                    )
                );
            } catch (IOException e) {
                listener.onFailure(e);
            } finally {
                Arrays.fill(secretHashChars, (char) 0);
            }
        }));
    }

    private static String keyIdToDocId(String keyId) {
        return "cross_cluster_key_" + keyId;
    }

    private static String docIdToKeyId(String docId) {
        assert docId.startsWith("cross_cluster_key_");
        return docId.substring("cross_cluster_key_".length());
    }

    public void updateCrossClusterKeys(
        final Authentication authentication,
        final BaseBulkUpdateApiKeyRequest request,
        final ActionListener<BulkUpdateApiKeyResponse> listener
    ) {
        final String[] crossClusterKeyIds = request.getIds().toArray(String[]::new);

        if (logger.isDebugEnabled()) {
            logger.debug("Updating [{}] cross cluster keys", Strings.arrayToCommaDelimitedString(crossClusterKeyIds));
        }
        findCrossClusterKeysForUserRealmCrossClusterKeyIdAndNameCombination(
            null,
            crossClusterKeyIds,
            CrossClusterKeyService::convertSearchHitToVersionedCrossClusterKeyDoc,
            ActionListener.wrap(
                versionedDocs -> updateCrossClusterKeys(request, versionedDocs, listener),
                ex -> listener.onFailure(traceLog("bulk update", ex))
            )
        );
    }

    private void updateCrossClusterKeys(
        final BaseBulkUpdateApiKeyRequest request,
        final Collection<VersionedCrossClusterKeyDoc> targetVersionedDocs,
        final ActionListener<BulkUpdateApiKeyResponse> listener
    ) {
        logger.trace("Found [{}] cross cluster keys of [{}] requested for update", targetVersionedDocs.size(), request.getIds().size());
        assert targetVersionedDocs.size() <= request.getIds().size()
            : "more docs were found for update than were requested. found: "
                + targetVersionedDocs.size()
                + " requested: "
                + request.getIds().size();

        final BulkUpdateApiKeyResponse.Builder responseBuilder = BulkUpdateApiKeyResponse.builder();
        final BulkRequestBuilder bulkRequestBuilder = client.prepareBulk();
        for (VersionedCrossClusterKeyDoc versionedDoc : targetVersionedDocs) {
            final String crossClusterKeyId = versionedDoc.id();
            try {
                final IndexRequest indexRequest = maybeBuildIndexRequest(versionedDoc, request);
                final boolean isNoop = indexRequest == null;
                if (isNoop) {
                    logger.debug("Detected noop update request for cross cluster key [{}]. Skipping index request", crossClusterKeyId);
                    responseBuilder.noop(crossClusterKeyId);
                } else {
                    bulkRequestBuilder.add(indexRequest);
                }
            } catch (Exception ex) {
                responseBuilder.error(crossClusterKeyId, traceLog("prepare index request for update", ex));
            }
        }
        addErrorsForNotFoundCrossClusterKeys(responseBuilder, targetVersionedDocs, request.getIds());
        if (bulkRequestBuilder.numberOfActions() == 0) {
            logger.trace("No bulk request execution necessary for cross cluster key update");
            listener.onResponse(responseBuilder.build());
            return;
        }

        logger.trace("Executing bulk request to update [{}] cross cluster keys", bulkRequestBuilder.numberOfActions());
        bulkRequestBuilder.setRefreshPolicy(RefreshPolicy.WAIT_UNTIL);
        securityIndex.prepareIndexIfNeededThenExecute(
            ex -> listener.onFailure(traceLog("prepare security index before update", ex)),
            () -> executeAsyncWithOrigin(
                client.threadPool().getThreadContext(),
                SECURITY_ORIGIN,
                bulkRequestBuilder.request(),
                ActionListener.<BulkResponse>wrap(
                    bulkResponse -> buildResponseAndClearCache(bulkResponse, responseBuilder, listener),
                    ex -> listener.onFailure(traceLog("execute bulk request for update", ex))
                ),
                client::bulk
            )
        );
    }

    /**
     * package-private for testing
     */
    static XContentBuilder newDocument(char[] secretHashChars, String name, List<RoleDescriptor> keyRoleDescriptors, Version version)
        throws IOException {
        final XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject().field("doc_type", "cross_cluster_key");

        addSecretHash(builder, secretHashChars);
        addRoleDescriptors(builder, keyRoleDescriptors);

        builder.field("name", name).field("version", version.id);
        return builder.endObject();
    }

    // package private for testing
    /**
     * @return `null` if the update is a noop, i.e., if no changes to `currentCrossClusterKeyDoc` are required
     */
    @Nullable
    XContentBuilder maybeBuildUpdatedDocument(
        final String crossClusterKeyId,
        final CrossClusterKeyDoc currentCrossClusterKeyDoc,
        final Version targetDocVersion,
        final BaseUpdateApiKeyRequest request
    ) throws IOException {
        if (isNoop(crossClusterKeyId, currentCrossClusterKeyDoc, targetDocVersion, request)) {
            return null;
        }

        final XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject().field("doc_type", "cross_cluster_key");

        addSecretHash(builder, currentCrossClusterKeyDoc.hash.toCharArray());

        final List<RoleDescriptor> keyRoles = request.getRoleDescriptors();
        if (keyRoles != null) {
            logger.trace(() -> format("Building cross cluster key doc with updated role descriptors [%s]", keyRoles));
            addRoleDescriptors(builder, keyRoles);
        } else {
            assert currentCrossClusterKeyDoc.roleDescriptorsBytes != null;
            builder.rawField("role_descriptors", currentCrossClusterKeyDoc.roleDescriptorsBytes.streamInput(), XContentType.JSON);
        }
        builder.field("name", currentCrossClusterKeyDoc.name).field("version", targetDocVersion.id);

        return builder.endObject();
    }

    private boolean isNoop(
        final String crossClusterKeyId,
        final CrossClusterKeyDoc crossClusterKeyDoc,
        final Version targetDocVersion,
        final BaseUpdateApiKeyRequest request
    ) {
        if (crossClusterKeyDoc.version != targetDocVersion.id) {
            return false;
        }

        final List<RoleDescriptor> newRoleDescriptors = request.getRoleDescriptors();
        if (newRoleDescriptors != null) {
            final List<RoleDescriptor> currentRoleDescriptors = parseRoleDescriptorsBytes(
                crossClusterKeyId,
                crossClusterKeyDoc.roleDescriptorsBytes
            );
            if (false == (newRoleDescriptors.size() == currentRoleDescriptors.size()
                && Set.copyOf(newRoleDescriptors).containsAll(currentRoleDescriptors))) {
                return false;
            }
        }

        return true;
    }

    void tryAuthenticate(ThreadContext ctx, CrossClusterKeyCredentials credentials, ActionListener<AuthenticationResult<User>> listener) {
        assert credentials != null : "cross cluster key credentials must not be null";
        loadCrossClusterKeyAndValidateCredentials(ctx, credentials, ActionListener.wrap(response -> {
            credentials.close();
            listener.onResponse(response);
        }, e -> {
            credentials.close();
            listener.onFailure(e);
        }));
    }

    void loadCrossClusterKeyAndValidateCredentials(
        ThreadContext ctx,
        CrossClusterKeyCredentials credentials,
        ActionListener<AuthenticationResult<User>> listener
    ) {
        final String docId = keyIdToDocId(credentials.getId());

        Consumer<CrossClusterKeyDoc> validator = crossClusterKeyDoc -> validateCrossClusterKeyCredentials(
            docId,
            crossClusterKeyDoc,
            credentials,
            listener.delegateResponse((l, e) -> {
                if (ExceptionsHelper.unwrapCause(e) instanceof EsRejectedExecutionException) {
                    l.onResponse(AuthenticationResult.terminate("server is too busy to respond", e));
                } else {
                    l.onFailure(e);
                }
            })
        );

        final long invalidationCount;
        if (docCache != null) {
            CrossClusterKeyDoc existing = docCache.get(docId);
            if (existing != null) {
                validator.accept(existing);
                return;
            }
            // cross cluster key doc not found in cache, take a record of the current invalidation count to prepare for caching
            invalidationCount = docCache.getInvalidationCount();
        } else {
            invalidationCount = -1;
        }

        final GetRequest getRequest = client.prepareGet(SECURITY_MAIN_ALIAS, docId).setFetchSource(true).request();
        executeAsyncWithOrigin(ctx, SECURITY_ORIGIN, getRequest, ActionListener.<GetResponse>wrap(response -> {
            if (response.isExists()) {
                final CrossClusterKeyDoc crossClusterKeyDoc;
                try (
                    XContentParser parser = XContentHelper.createParser(
                        XContentParserConfiguration.EMPTY.withDeprecationHandler(LoggingDeprecationHandler.INSTANCE),
                        response.getSourceAsBytesRef(),
                        XContentType.JSON
                    )
                ) {
                    crossClusterKeyDoc = CrossClusterKeyDoc.fromXContent(parser);
                }
                if (invalidationCount != -1) {
                    docCache.putIfNoInvalidationSince(docId, crossClusterKeyDoc, invalidationCount);
                }
                validator.accept(crossClusterKeyDoc);
            } else {
                if (authCache != null) {
                    authCache.invalidate(docId);
                }
                listener.onResponse(
                    AuthenticationResult.unsuccessful("unable to find cross cluster key with id " + credentials.getId(), null)
                );
            }
        }, e -> {
            if (ExceptionsHelper.unwrapCause(e) instanceof EsRejectedExecutionException) {
                listener.onResponse(AuthenticationResult.terminate("server is too busy to respond", e));
            } else {
                listener.onResponse(
                    AuthenticationResult.unsuccessful(
                        "cross cluster key authentication for id " + credentials.getId() + " encountered a failure",
                        e
                    )
                );
            }
        }), client::get);
    }

    private List<RoleDescriptor> parseRoleDescriptorsBytes(final String crossClusterKeyId, BytesReference bytesReference) {
        if (bytesReference == null) {
            return Collections.emptyList();
        }

        List<RoleDescriptor> roleDescriptors = new ArrayList<>();
        try (
            XContentParser parser = XContentHelper.createParser(
                XContentParserConfiguration.EMPTY.withDeprecationHandler(LoggingDeprecationHandler.INSTANCE),
                bytesReference,
                XContentType.JSON
            )
        ) {
            parser.nextToken(); // skip outer start object
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                parser.nextToken(); // role name
                String roleName = parser.currentName();
                roleDescriptors.add(RoleDescriptor.parse(roleName, parser, false));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return roleDescriptors;
    }

    /**
     * Validates the cross cluster key using the source map
     * @param docId the identifier of the document that was retrieved from the security index
     * @param crossClusterKeyDoc the partially deserialized cross cluster key document
     * @param credentials the credentials provided by the user
     * @param listener the listener to notify after verification
     */
    void validateCrossClusterKeyCredentials(
        String docId,
        CrossClusterKeyDoc crossClusterKeyDoc,
        CrossClusterKeyCredentials credentials,
        ActionListener<AuthenticationResult<User>> listener
    ) {
        if ("cross_cluster_key".equals(crossClusterKeyDoc.docType) == false) {
            listener.onResponse(
                AuthenticationResult.unsuccessful(
                    "document [" + docId + "] is [" + crossClusterKeyDoc.docType + "] not an cross cluster key",
                    null
                )
            );
        } else {
            if (crossClusterKeyDoc.hash == null) {
                throw new IllegalStateException("cross cluster key hash is missing");
            }

            if (authCache != null) {
                final AtomicBoolean valueAlreadyInCache = new AtomicBoolean(true);
                final ListenableFuture<CachedCrossClusterKeyHashResult> listenableCacheEntry;
                try {
                    listenableCacheEntry = authCache.computeIfAbsent(credentials.getId(), k -> {
                        valueAlreadyInCache.set(false);
                        return new ListenableFuture<>();
                    });
                } catch (ExecutionException e) {
                    listener.onFailure(e);
                    return;
                }

                if (valueAlreadyInCache.get()) {
                    listenableCacheEntry.addListener(ActionListener.wrap(result -> {
                        if (result.success) {
                            if (result.verify(credentials.getKey())) {
                                // move on
                                validateCrossClusterKey(crossClusterKeyDoc, credentials, listener);
                            } else {
                                listener.onResponse(
                                    AuthenticationResult.unsuccessful(
                                        "invalid credentials for cross cluster key [" + credentials.getId() + "]",
                                        null
                                    )
                                );
                            }
                        } else if (result.verify(credentials.getKey())) { // same key, pass the same result
                            listener.onResponse(
                                AuthenticationResult.unsuccessful(
                                    "invalid credentials for cross cluster key [" + credentials.getId() + "]",
                                    null
                                )
                            );
                        } else {
                            authCache.invalidate(credentials.getId(), listenableCacheEntry);
                            validateCrossClusterKeyCredentials(docId, crossClusterKeyDoc, credentials, listener);
                        }
                    }, listener::onFailure), threadPool.generic(), threadPool.getThreadContext());
                } else {
                    verifyKeyAgainstHash(crossClusterKeyDoc.hash, credentials, ActionListener.wrap(verified -> {
                        listenableCacheEntry.onResponse(new CachedCrossClusterKeyHashResult(verified, credentials.getKey()));
                        if (verified) {
                            // move on
                            validateCrossClusterKey(crossClusterKeyDoc, credentials, listener);
                        } else {
                            listener.onResponse(
                                AuthenticationResult.unsuccessful(
                                    "invalid credentials for cross cluster key [" + credentials.getId() + "]",
                                    null
                                )
                            );
                        }
                    }, listener::onFailure));
                }
            } else {
                verifyKeyAgainstHash(crossClusterKeyDoc.hash, credentials, ActionListener.wrap(verified -> {
                    if (verified) {
                        // move on
                        validateCrossClusterKey(crossClusterKeyDoc, credentials, listener);
                    } else {
                        listener.onResponse(
                            AuthenticationResult.unsuccessful(
                                "invalid credentials for cross cluster key [" + credentials.getId() + "]",
                                null
                            )
                        );
                    }
                }, listener::onFailure));
            }
        }
    }

    // package-private for testing
    static void validateCrossClusterKey(
        CrossClusterKeyDoc crossClusterKeyDoc,
        CrossClusterKeyCredentials credentials,
        ActionListener<AuthenticationResult<User>> listener
    ) {
        final Map<String, Object> authResultMetadata = new HashMap<>();
        // TODO: use different metadata keys
        authResultMetadata.put(AuthenticationField.API_KEY_ROLE_DESCRIPTORS_KEY, crossClusterKeyDoc.roleDescriptorsBytes);
        authResultMetadata.put(AuthenticationField.API_KEY_ID_KEY, credentials.getId());
        authResultMetadata.put(AuthenticationField.API_KEY_NAME_KEY, crossClusterKeyDoc.name);
        authResultMetadata.put(AuthenticationField.API_KEY_TYPE_KEY, ApiKey.Type.CROSS_CLUSTER.value());
        listener.onResponse(AuthenticationResult.success(new User("cross_cluster_key/" + credentials.getId()), authResultMetadata));
    }

    static CrossClusterKeyCredentials getCredentialsFromHeader(String header) {
        return parseCrossClusterKey(Authenticator.extractCredentialFromHeaderValue(header, "ApiKey"));
    }

    private static CrossClusterKeyCredentials parseCrossClusterKey(SecureString crossClusterKeyString) {
        if (crossClusterKeyString != null) {
            if (false == (crossClusterKeyString.charAt(0) == 'c'
                && crossClusterKeyString.charAt(1) == 'c'
                && crossClusterKeyString.charAt(2) == '_')) {
                throw new IllegalArgumentException("invalid cross cluster key prefix");
            }
            final byte[] decodedCrossClusterKeyCredBytes = Base64.getDecoder()
                .decode(
                    CharArrays.toUtf8Bytes(Arrays.copyOfRange(crossClusterKeyString.getChars(), 3, crossClusterKeyString.getChars().length))
                );
            char[] crossClusterKeyCredChars = null;
            try {
                crossClusterKeyCredChars = CharArrays.utf8BytesToChars(decodedCrossClusterKeyCredBytes);
                int colonIndex = -1;
                for (int i = 0; i < crossClusterKeyCredChars.length; i++) {
                    if (crossClusterKeyCredChars[i] == ':') {
                        colonIndex = i;
                        break;
                    }
                }

                if (colonIndex < 1) {
                    throw new IllegalArgumentException("invalid cross cluster key value");
                }
                return new CrossClusterKeyCredentials(
                    new String(Arrays.copyOfRange(crossClusterKeyCredChars, 0, colonIndex)),
                    new SecureString(Arrays.copyOfRange(crossClusterKeyCredChars, colonIndex + 1, crossClusterKeyCredChars.length))
                );
            } finally {
                if (crossClusterKeyCredChars != null) {
                    Arrays.fill(crossClusterKeyCredChars, (char) 0);
                }
            }
        }
        return null;
    }

    void computeHashForSecret(SecureString secret, ActionListener<char[]> listener) {
        threadPool.executor(SECURITY_CRYPTO_THREAD_POOL_NAME).execute(ActionRunnable.supply(listener, () -> hasher.hash(secret)));
    }

    // Protected instance method so this can be mocked
    protected void verifyKeyAgainstHash(
        String crossClusterKeyHash,
        CrossClusterKeyCredentials credentials,
        ActionListener<Boolean> listener
    ) {
        threadPool.executor(SECURITY_CRYPTO_THREAD_POOL_NAME).execute(ActionRunnable.supply(listener, () -> {
            Hasher hasher = Hasher.resolveFromHash(crossClusterKeyHash.toCharArray());
            final char[] crossClusterKeyHashChars = crossClusterKeyHash.toCharArray();
            try {
                return hasher.verify(credentials.getKey(), crossClusterKeyHashChars);
            } finally {
                Arrays.fill(crossClusterKeyHashChars, (char) 0);
            }
        }));
    }

    // public class for testing
    public static final class CrossClusterKeyCredentials implements AuthenticationToken, Closeable {
        private final String id;
        private final SecureString key;

        public CrossClusterKeyCredentials(String id, SecureString key) {
            this.id = id;
            this.key = key;
        }

        String getId() {
            return id;
        }

        SecureString getKey() {
            return key;
        }

        @Override
        public void close() {
            key.close();
        }

        @Override
        public String principal() {
            return id;
        }

        @Override
        public Object credentials() {
            return key;
        }

        @Override
        public void clearCredentials() {
            close();
        }

    }

    /**
     * @return `null` if the update is a noop, i.e., if no changes to `currentCrossClusterKeyDoc` are required
     */
    @Nullable
    private IndexRequest maybeBuildIndexRequest(
        final VersionedCrossClusterKeyDoc currentVersionedDoc,
        final BaseUpdateApiKeyRequest request
    ) throws IOException {
        if (logger.isTraceEnabled()) {
            logger.trace(
                "Building index request for update of cross cluster key doc [{}] with seqNo [{}] and primaryTerm [{}]",
                currentVersionedDoc.id(),
                currentVersionedDoc.seqNo(),
                currentVersionedDoc.primaryTerm()
            );
        }
        final var targetDocVersion = clusterService.state().nodes().getMinNodeVersion();
        final var currentDocVersion = Version.fromId(currentVersionedDoc.doc().version);
        assert currentDocVersion.onOrBefore(targetDocVersion) : "current cross cluster key doc version must be on or before target version";
        if (logger.isDebugEnabled() && currentDocVersion.before(targetDocVersion)) {
            logger.debug(
                "cross cluster key update for [{}] will update version from [{}] to [{}]",
                currentVersionedDoc.id(),
                currentDocVersion,
                targetDocVersion
            );
        }
        final XContentBuilder builder = maybeBuildUpdatedDocument(
            currentVersionedDoc.id(),
            currentVersionedDoc.doc(),
            targetDocVersion,
            request
        );
        final boolean isNoop = builder == null;
        return isNoop
            ? null
            : client.prepareIndex(SECURITY_MAIN_ALIAS)
                .setId(keyIdToDocId(currentVersionedDoc.id()))
                .setSource(builder)
                .setIfSeqNo(currentVersionedDoc.seqNo())
                .setIfPrimaryTerm(currentVersionedDoc.primaryTerm())
                .setOpType(DocWriteRequest.OpType.INDEX)
                .request();
    }

    private void addErrorsForNotFoundCrossClusterKeys(
        final BulkUpdateApiKeyResponse.Builder responseBuilder,
        final Collection<VersionedCrossClusterKeyDoc> foundDocs,
        final List<String> requestedIds
    ) {
        // Short-circuiting by size is safe: `foundDocs` only contains unique IDs of those requested. Same size here necessarily implies
        // same content
        if (foundDocs.size() == requestedIds.size()) {
            return;
        }
        final Set<String> foundIds = foundDocs.stream().map(VersionedCrossClusterKeyDoc::id).collect(Collectors.toUnmodifiableSet());
        for (String id : requestedIds) {
            if (foundIds.contains(id) == false) {
                responseBuilder.error(
                    id,
                    new ResourceNotFoundException("no cross cluster key owned by requesting user found for ID [" + id + "]")
                );
            }
        }
    }

    /**
     * Invalidate cross cluster keys for given realm, username, cross cluster key name and id.
     * @param realmNames realm names
     * @param username user name
     * @param crossClusterKeyName cross cluster key name
     * @param crossClusterKeyIds cross cluster key ids
     * @param invalidateListener listener for {@link InvalidateApiKeyResponse}
     */
    public void invalidateApiKeys(
        String[] realmNames,
        String username,
        String crossClusterKeyName,
        String[] crossClusterKeyIds,
        ActionListener<InvalidateApiKeyResponse> invalidateListener
    ) {
        if ((realmNames == null || realmNames.length == 0)
            && Strings.hasText(username) == false
            && Strings.hasText(crossClusterKeyName) == false
            && (crossClusterKeyIds == null || crossClusterKeyIds.length == 0)) {
            logger.trace(
                "none of the parameters [cross cluster key id, cross cluster key name, username, realm name] "
                    + "were specified for invalidation"
            );
            invalidateListener.onFailure(
                new IllegalArgumentException(
                    "One of [cross cluster key id, cross cluster key name, username, realm name] must be specified"
                )
            );
        } else {
            findCrossClusterKeysForUserRealmCrossClusterKeyIdAndNameCombination(
                crossClusterKeyName,
                crossClusterKeyIds,
                // TODO: instead of parsing the entire cross cluster key document, we can just convert the hit to the cross cluster key ID
                this::convertSearchHitToCrossClusterKeyInfo,
                ActionListener.wrap(crossClusterKeys -> {
                    if (crossClusterKeys.isEmpty()) {
                        logger.debug(
                            "No active cross cluster keys to invalidate for realms {}, username [{}], "
                                + "cross cluster key name [{}] and cross cluster key ids {}",
                            Arrays.toString(realmNames),
                            username,
                            crossClusterKeyName,
                            Arrays.toString(crossClusterKeyIds)
                        );
                        invalidateListener.onResponse(InvalidateApiKeyResponse.emptyResponse());
                    } else {
                        indexInvalidation(
                            crossClusterKeys.stream().map(CrossClusterKey::id).collect(Collectors.toSet()),
                            invalidateListener
                        );
                    }
                }, invalidateListener::onFailure)
            );
        }
    }

    private <T> void findCrossClusterKeys(
        final BoolQueryBuilder boolQuery,
        final Function<SearchHit, T> hitParser,
        final ActionListener<Collection<T>> listener
    ) {
        final Supplier<ThreadContext.StoredContext> supplier = client.threadPool().getThreadContext().newRestorableContext(false);
        try (ThreadContext.StoredContext ignore = client.threadPool().getThreadContext().stashWithOrigin(SECURITY_ORIGIN)) {
            final SearchRequest request = client.prepareSearch(SECURITY_MAIN_ALIAS)
                .setScroll(DEFAULT_KEEPALIVE_SETTING.get(settings))
                .setQuery(boolQuery)
                .setVersion(false)
                .setSize(1000)
                .setFetchSource(true)
                .request();
            securityIndex.checkIndexVersionThenExecute(
                listener::onFailure,
                () -> ScrollHelper.fetchAllByEntity(client, request, new ContextPreservingActionListener<>(supplier, listener), hitParser)
            );
        }
    }

    private <T> void findCrossClusterKeysForUserRealmCrossClusterKeyIdAndNameCombination(
        String crossClusterKeyName,
        String[] crossClusterKeyIds,
        Function<SearchHit, T> hitParser,
        ActionListener<Collection<T>> listener
    ) {
        final SecurityIndexManager frozenSecurityIndex = securityIndex.freeze();
        if (frozenSecurityIndex.indexExists() == false) {
            listener.onResponse(Collections.emptyList());
        } else if (frozenSecurityIndex.isAvailable() == false) {
            listener.onFailure(frozenSecurityIndex.getUnavailableReason());
        } else {
            final BoolQueryBuilder boolQuery = QueryBuilders.boolQuery().filter(QueryBuilders.termQuery("doc_type", "cross_cluster_key"));
            if (Strings.hasText(crossClusterKeyName) && "*".equals(crossClusterKeyName) == false) {
                if (crossClusterKeyName.endsWith("*")) {
                    boolQuery.filter(QueryBuilders.prefixQuery("name", crossClusterKeyName.substring(0, crossClusterKeyName.length() - 1)));
                } else {
                    boolQuery.filter(QueryBuilders.termQuery("name", crossClusterKeyName));
                }
            }
            if (crossClusterKeyIds != null && crossClusterKeyIds.length > 0) {
                boolQuery.filter(
                    QueryBuilders.idsQuery()
                        .addIds(Arrays.stream(crossClusterKeyIds).map(CrossClusterKeyService::keyIdToDocId).toArray(String[]::new))
                );
            }

            findCrossClusterKeys(boolQuery, hitParser, listener);
        }
    }

    /**
     * Performs the actual invalidation of a collection of cross cluster keys
     *
     * @param crossClusterKeyIds the cross cluster keys to invalidate
     * @param listener  the listener to notify upon completion
     */
    private void indexInvalidation(Collection<String> crossClusterKeyIds, ActionListener<InvalidateApiKeyResponse> listener) {
        if (crossClusterKeyIds.isEmpty()) {
            listener.onFailure(new ElasticsearchSecurityException("No cross cluster key ids provided for invalidation"));
        } else {
            BulkRequestBuilder bulkRequestBuilder = client.prepareBulk();
            for (String crossClusterKeyId : crossClusterKeyIds) {
                // TODO: change to deletion
                UpdateRequest request = client.prepareUpdate(SECURITY_MAIN_ALIAS, crossClusterKeyId).request();
                bulkRequestBuilder.add(request);
            }
            bulkRequestBuilder.setRefreshPolicy(RefreshPolicy.WAIT_UNTIL);
            securityIndex.prepareIndexIfNeededThenExecute(
                ex -> listener.onFailure(traceLog("prepare security index", ex)),
                () -> executeAsyncWithOrigin(
                    client.threadPool().getThreadContext(),
                    SECURITY_ORIGIN,
                    bulkRequestBuilder.request(),
                    ActionListener.<BulkResponse>wrap(bulkResponse -> {
                        ArrayList<ElasticsearchException> failedRequestResponses = new ArrayList<>();
                        ArrayList<String> previouslyInvalidated = new ArrayList<>();
                        ArrayList<String> invalidated = new ArrayList<>();
                        for (BulkItemResponse bulkItemResponse : bulkResponse.getItems()) {
                            if (bulkItemResponse.isFailed()) {
                                Throwable cause = bulkItemResponse.getFailure().getCause();
                                final String failedCrossClusterKeyId = bulkItemResponse.getFailure().getId();
                                traceLog("invalidate cross cluster key", failedCrossClusterKeyId, cause);
                                failedRequestResponses.add(new ElasticsearchException("Error invalidating cross cluster key", cause));
                            } else {
                                UpdateResponse updateResponse = bulkItemResponse.getResponse();
                                if (updateResponse.getResult() == DocWriteResponse.Result.UPDATED) {
                                    logger.debug("Invalidated cross cluster key for doc [{}]", updateResponse.getId());
                                    invalidated.add(updateResponse.getId());
                                } else if (updateResponse.getResult() == DocWriteResponse.Result.NOOP) {
                                    previouslyInvalidated.add(updateResponse.getId());
                                }
                            }
                        }
                        InvalidateApiKeyResponse result = new InvalidateApiKeyResponse(
                            invalidated,
                            previouslyInvalidated,
                            failedRequestResponses
                        );
                        clearCache(result, listener);
                    }, e -> {
                        Throwable cause = ExceptionsHelper.unwrapCause(e);
                        traceLog("invalidate cross cluster keys", cause);
                        listener.onFailure(e);
                    }),
                    client::bulk
                )
            );
        }
    }

    private void buildResponseAndClearCache(
        final BulkResponse bulkResponse,
        final BulkUpdateApiKeyResponse.Builder responseBuilder,
        final ActionListener<BulkUpdateApiKeyResponse> listener
    ) {
        for (BulkItemResponse bulkItemResponse : bulkResponse.getItems()) {
            final String crossClusterKeyId = bulkItemResponse.getId();
            if (bulkItemResponse.isFailed()) {
                responseBuilder.error(
                    crossClusterKeyId,
                    new ElasticsearchException("bulk request execution failure", bulkItemResponse.getFailure().getCause())
                );
            } else {
                // Since we made an index request against an existing document, we can't get a NOOP or CREATED here
                assert bulkItemResponse.getResponse().getResult() == DocWriteResponse.Result.UPDATED;
                responseBuilder.updated(crossClusterKeyId);
            }
        }
        clearCrossClusterKeyDocCache(responseBuilder.build(), listener);
    }

    private static void addSecretHash(final XContentBuilder builder, final char[] secretHashChars) throws IOException {
        byte[] utf8Bytes = null;
        try {
            utf8Bytes = CharArrays.toUtf8Bytes(secretHashChars);
            builder.field("password").utf8Value(utf8Bytes, 0, utf8Bytes.length);
        } finally {
            if (utf8Bytes != null) {
                Arrays.fill(utf8Bytes, (byte) 0);
            }
        }
    }

    private static void addRoleDescriptors(final XContentBuilder builder, final List<RoleDescriptor> keyRoles) throws IOException {
        builder.startObject("role_descriptors");
        if (keyRoles != null && keyRoles.isEmpty() == false) {
            for (RoleDescriptor descriptor : keyRoles) {
                builder.field(descriptor.getName(), (contentBuilder, params) -> descriptor.toXContent(contentBuilder, params, true));
            }
        }
        builder.endObject();
    }

    private void clearCache(InvalidateApiKeyResponse result, ActionListener<InvalidateApiKeyResponse> listener) {
        executeClearCacheRequest(
            result,
            listener,
            new ClearSecurityCacheRequest().cacheName("cross_cluster_key").keys(result.getInvalidatedApiKeys().toArray(String[]::new))
        );
    }

    private void clearCrossClusterKeyDocCache(
        final BulkUpdateApiKeyResponse result,
        final ActionListener<BulkUpdateApiKeyResponse> listener
    ) {
        executeClearCacheRequest(
            result,
            listener,
            new ClearSecurityCacheRequest().cacheName("cross_cluster_key_doc").keys(result.getUpdated().toArray(String[]::new))
        );
    }

    private <T> void executeClearCacheRequest(
        T result,
        ActionListener<T> listener,
        ClearSecurityCacheRequest clearCrossClusterKeyCacheRequest
    ) {
        executeAsyncWithOrigin(
            client,
            SECURITY_ORIGIN,
            ClearSecurityCacheAction.INSTANCE,
            clearCrossClusterKeyCacheRequest,
            new ActionListener<>() {
                @Override
                public void onResponse(ClearSecurityCacheResponse nodes) {
                    listener.onResponse(result);
                }

                @Override
                public void onFailure(Exception e) {
                    logger.error(
                        () -> format("unable to clear cross cluster key cache [%s]", clearCrossClusterKeyCacheRequest.cacheName()),
                        e
                    );
                    listener.onFailure(
                        new ElasticsearchException("clearing the cross cluster key cache failed; please clear the caches manually", e)
                    );
                }
            }
        );
    }

    /**
     * Logs an exception concerning a specific cross cluster key at TRACE level (if enabled)
     */
    private static <E extends Throwable> E traceLog(String action, String identifier, E exception) {
        if (logger.isTraceEnabled()) {
            if (exception instanceof final ElasticsearchException esEx) {
                final Object detail = esEx.getHeader("error_description");
                if (detail != null) {
                    logger.trace(() -> format("Failure in [%s] for id [%s] - [%s]", action, identifier, detail), esEx);
                } else {
                    logger.trace(() -> format("Failure in [%s] for id [%s]", action, identifier), esEx);
                }
            } else {
                logger.trace(() -> format("Failure in [%s] for id [%s]", action, identifier), exception);
            }
        }
        return exception;
    }

    /**
     * Logs an exception at TRACE level (if enabled)
     */
    private static <E extends Throwable> E traceLog(String action, E exception) {
        if (logger.isTraceEnabled()) {
            if (exception instanceof final ElasticsearchException esEx) {
                final Object detail = esEx.getHeader("error_description");
                if (detail != null) {
                    logger.trace(() -> format("Failure in [%s] - [%s]", action, detail), esEx);
                } else {
                    logger.trace(() -> "Failure in [" + action + "]", esEx);
                }
            } else {
                logger.trace(() -> "Failure in [" + action + "]", exception);
            }
        }
        return exception;
    }

    /**
     * Get cross cluster key information for given realm, user, cross cluster key name and id combination
     * @param realmNames realm names
     * @param username user name
     * @param crossClusterKeyName cross cluster key name
     * @param crossClusterKeyIds cross cluster key ids
     * @param listener listener for {@link GetCrossClusterKeyResponse}
     */
    public void getCrossClusterKeys(
        String[] realmNames,
        String username,
        String crossClusterKeyName,
        String[] crossClusterKeyIds,
        ActionListener<GetCrossClusterKeyResponse> listener
    ) {
        findCrossClusterKeysForUserRealmCrossClusterKeyIdAndNameCombination(
            crossClusterKeyName,
            crossClusterKeyIds,
            this::convertSearchHitToCrossClusterKeyInfo,
            ActionListener.wrap(crossClusterKeyInfos -> {
                if (crossClusterKeyInfos.isEmpty()) {
                    logger.debug(
                        "No active cross cluster keys found for realms {}, user [{}], "
                            + "cross cluster key name [{}] and cross cluster key ids {}",
                        Arrays.toString(realmNames),
                        username,
                        crossClusterKeyName,
                        Arrays.toString(crossClusterKeyIds)
                    );
                    listener.onResponse(new GetCrossClusterKeyResponse(List.of()));
                } else {
                    listener.onResponse(new GetCrossClusterKeyResponse(crossClusterKeyInfos));
                }
            }, listener::onFailure)
        );
    }

    private CrossClusterKey convertSearchHitToCrossClusterKeyInfo(SearchHit hit) {
        final CrossClusterKeyDoc crossClusterKeyDoc = convertSearchHitToVersionedCrossClusterKeyDoc(hit).doc;
        final String crossClusterKeyId = docIdToKeyId(hit.getId());

        final List<RoleDescriptor> roleDescriptors = parseRoleDescriptorsBytes(crossClusterKeyId, crossClusterKeyDoc.roleDescriptorsBytes);

        return new CrossClusterKey(crossClusterKeyDoc.name, crossClusterKeyId, roleDescriptors);
    }

    private static VersionedCrossClusterKeyDoc convertSearchHitToVersionedCrossClusterKeyDoc(SearchHit hit) {
        try (
            XContentParser parser = XContentHelper.createParser(XContentParserConfiguration.EMPTY, hit.getSourceRef(), XContentType.JSON)
        ) {
            return new VersionedCrossClusterKeyDoc(
                CrossClusterKeyDoc.fromXContent(parser),
                docIdToKeyId(hit.getId()),
                hit.getSeqNo(),
                hit.getPrimaryTerm()
            );
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private record VersionedCrossClusterKeyDoc(CrossClusterKeyDoc doc, String id, long seqNo, long primaryTerm) {}

    final class CachedCrossClusterKeyHashResult {
        final boolean success;
        final char[] hash;

        CachedCrossClusterKeyHashResult(boolean success, SecureString secret) {
            this.success = success;
            this.hash = cacheHasher.hash(secret);
        }

        boolean verify(SecureString password) {
            return hash != null && cacheHasher.verify(password, hash);
        }
    }

    public static final class CrossClusterKeyDoc {

        static final InstantiatingObjectParser<CrossClusterKeyDoc, Void> PARSER;
        static {
            InstantiatingObjectParser.Builder<CrossClusterKeyDoc, Void> builder = InstantiatingObjectParser.builder(
                "cross_cluster_key_doc",
                true,
                CrossClusterKeyDoc.class
            );
            builder.declareString(constructorArg(), new ParseField("doc_type"));
            builder.declareString(constructorArg(), new ParseField("password"));
            builder.declareStringOrNull(optionalConstructorArg(), new ParseField("name"));
            builder.declareInt(constructorArg(), new ParseField("version"));
            ObjectParserHelper.declareRawObject(builder, constructorArg(), new ParseField("role_descriptors"));
            PARSER = builder.build();
        }

        // TODO: Add a field for ID
        final String docType;
        final String hash;
        @Nullable
        final String name;
        final int version;
        final BytesReference roleDescriptorsBytes;

        public CrossClusterKeyDoc(String docType, String hash, @Nullable String name, int version, BytesReference roleDescriptorsBytes) {
            this.docType = docType;
            this.hash = hash;
            this.name = name;
            this.version = version;
            this.roleDescriptorsBytes = roleDescriptorsBytes;
        }

        public CachedCrossClusterKeyDoc toCachedCrossClusterKeyDoc() {
            final MessageDigest digest = MessageDigests.sha256();
            final String roleDescriptorsHash = MessageDigests.toHexString(MessageDigests.digest(roleDescriptorsBytes, digest));
            digest.reset();
            return new CachedCrossClusterKeyDoc(hash, name, version, roleDescriptorsHash);
        }

        static CrossClusterKeyDoc fromXContent(XContentParser parser) {
            return PARSER.apply(parser, null);
        }
    }

    /**
     * A cached version of the {@link CrossClusterKeyDoc}. The main difference is that the role descriptors
     * are replaced by their hashes. The actual values are stored in a separate role descriptor cache,
     * so that duplicate role descriptors are cached only once (and therefore consume less memory).
     */
    public static final class CachedCrossClusterKeyDoc {
        final String hash;
        final String name;
        final int version;
        final String roleDescriptorsHash;

        public CachedCrossClusterKeyDoc(String hash, String name, int version, String roleDescriptorsHash) {
            this.hash = hash;
            this.name = name;
            this.version = version;
            this.roleDescriptorsHash = roleDescriptorsHash;
        }

        public CrossClusterKeyDoc toCrossClusterKeyDoc(BytesReference roleDescriptorsBytes) {
            return new CrossClusterKeyDoc("cross_cluster_key", hash, name, version, roleDescriptorsBytes);
        }
    }

    private static final class DocCache {
        private final Cache<String, CachedCrossClusterKeyDoc> docCache;
        private final Cache<String, BytesReference> roleDescriptorsBytesCache;
        private final LockingAtomicCounter lockingAtomicCounter;

        DocCache(TimeValue ttl, int maximumWeight) {
            this.docCache = CacheBuilder.<String, CachedCrossClusterKeyDoc>builder()
                .setMaximumWeight(maximumWeight)
                .setExpireAfterWrite(ttl)
                .build();
            // We don't use the doc TTL because that TTL is very low to avoid the risk of
            // caching an invalidated cross cluster key. But role descriptors are immutable and may be shared between
            // multiple cross cluster keys, so we cache for longer and rely on the weight to manage the cache size.
            this.roleDescriptorsBytesCache = CacheBuilder.<String, BytesReference>builder()
                .setExpireAfterAccess(TimeValue.timeValueHours(1))
                .setMaximumWeight(maximumWeight * 2L)
                .build();
            this.lockingAtomicCounter = new LockingAtomicCounter();
        }

        public CrossClusterKeyDoc get(String docId) {
            CachedCrossClusterKeyDoc existing = docCache.get(docId);
            if (existing != null) {
                final BytesReference roleDescriptorsBytes = roleDescriptorsBytesCache.get(existing.roleDescriptorsHash);
                if (roleDescriptorsBytes != null) {
                    return existing.toCrossClusterKeyDoc(roleDescriptorsBytes);
                }
            }
            return null;
        }

        public long getInvalidationCount() {
            return lockingAtomicCounter.get();
        }

        public void putIfNoInvalidationSince(String docId, CrossClusterKeyDoc crossClusterKeyDoc, long invalidationCount) {
            final CachedCrossClusterKeyDoc cachedCrossClusterKeyDoc = crossClusterKeyDoc.toCachedCrossClusterKeyDoc();
            lockingAtomicCounter.compareAndRun(invalidationCount, () -> {
                docCache.put(docId, cachedCrossClusterKeyDoc);
                try {
                    roleDescriptorsBytesCache.computeIfAbsent(
                        cachedCrossClusterKeyDoc.roleDescriptorsHash,
                        k -> crossClusterKeyDoc.roleDescriptorsBytes
                    );
                } catch (ExecutionException e) {
                    throw new RuntimeException(e);
                }
            });
        }

        public void invalidate(Collection<String> docIds) {
            lockingAtomicCounter.increment();
            logger.debug("Invalidating cross cluster key doc cache with ids: [{}]", Strings.collectionToCommaDelimitedString(docIds));
            docIds.forEach(docCache::invalidate);
        }

        public void invalidateAll() {
            lockingAtomicCounter.increment();
            logger.debug("Invalidating all cross cluster key doc cache and descriptor cache");
            docCache.invalidateAll();
            roleDescriptorsBytesCache.invalidateAll();
        }
    }
}
