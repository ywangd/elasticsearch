/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authc;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRunnable;
import org.elasticsearch.action.DocWriteResponse;
import org.elasticsearch.action.bulk.BulkAction;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.bulk.TransportSingleItemBulkWriteAction;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.ContextPreservingActionListener;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.action.update.UpdateResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.CharArrays;
import org.elasticsearch.common.CheckedBiConsumer;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.UUIDs;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.cache.Cache;
import org.elasticsearch.common.cache.CacheBuilder;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.hash.MessageDigests;
import org.elasticsearch.common.logging.DeprecationLogger;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.EsRejectedExecutionException;
import org.elasticsearch.common.util.concurrent.FutureUtils;
import org.elasticsearch.common.util.concurrent.ListenableFuture;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.DeprecationHandler;
import org.elasticsearch.common.xcontent.InstantiatingObjectParser;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.ObjectParserHelper;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentLocation;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.license.LicenseUtils;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xpack.core.XPackSettings;
import org.elasticsearch.xpack.core.security.ScrollHelper;
import org.elasticsearch.xpack.core.security.action.ApiKey;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyResponse;
import org.elasticsearch.xpack.core.security.action.GetApiKeyResponse;
import org.elasticsearch.xpack.core.security.action.InvalidateApiKeyResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.Authentication.RealmRef;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.authc.support.Hasher;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.user.User;
import org.elasticsearch.xpack.security.support.FeatureNotEnabledException;
import org.elasticsearch.xpack.security.support.FeatureNotEnabledException.Feature;
import org.elasticsearch.xpack.security.support.SecurityIndexManager;

import javax.crypto.SecretKeyFactory;
import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.elasticsearch.common.xcontent.ConstructingObjectParser.constructorArg;
import static org.elasticsearch.common.xcontent.ConstructingObjectParser.optionalConstructorArg;
import static org.elasticsearch.action.bulk.TransportSingleItemBulkWriteAction.toSingleItemBulkRequest;
import static org.elasticsearch.search.SearchService.DEFAULT_KEEPALIVE_SETTING;
import static org.elasticsearch.xpack.core.ClientHelper.SECURITY_ORIGIN;
import static org.elasticsearch.xpack.core.ClientHelper.executeAsyncWithOrigin;
import static org.elasticsearch.xpack.core.security.authc.Authentication.AuthenticationType;
import static org.elasticsearch.xpack.core.security.authc.Authentication.VERSION_API_KEY_ROLES_AS_BYTES;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.API_KEY_LIMITED_ROLE_DESCRIPTORS_KEY;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.API_KEY_ROLE_DESCRIPTORS_KEY;
import static org.elasticsearch.xpack.core.security.index.RestrictedIndicesNames.SECURITY_MAIN_ALIAS;
import static org.elasticsearch.xpack.security.Security.SECURITY_CRYPTO_THREAD_POOL_NAME;

public class ApiKeyService {

    private static final Logger logger = LogManager.getLogger(ApiKeyService.class);
    private static final DeprecationLogger deprecationLogger = DeprecationLogger.getLogger(ApiKeyService.class);
    public static final String API_KEY_ID_KEY = "_security_api_key_id";
    public static final String API_KEY_NAME_KEY = "_security_api_key_name";
    public static final String API_KEY_REALM_NAME = "_es_api_key";
    public static final String API_KEY_REALM_TYPE = "_es_api_key";
    public static final String API_KEY_CREATOR_REALM_NAME = "_security_api_key_creator_realm_name";
    public static final String API_KEY_CREATOR_REALM_TYPE = "_security_api_key_creator_realm_type";

    public static final Setting<String> PASSWORD_HASHING_ALGORITHM = new Setting<>(
        "xpack.security.authc.api_key.hashing.algorithm", "pbkdf2", Function.identity(), v -> {
        if (Hasher.getAvailableAlgoStoredHash().contains(v.toLowerCase(Locale.ROOT)) == false) {
            throw new IllegalArgumentException("Invalid algorithm: " + v + ". Valid values for password hashing are " +
                Hasher.getAvailableAlgoStoredHash().toString());
        } else if (v.regionMatches(true, 0, "pbkdf2", 0, "pbkdf2".length())) {
            try {
                SecretKeyFactory.getInstance("PBKDF2withHMACSHA512");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalArgumentException(
                    "Support for PBKDF2WithHMACSHA512 must be available in order to use any of the " +
                        "PBKDF2 algorithms for the [xpack.security.authc.api_key.hashing.algorithm] setting.", e);
            }
        }
    }, Setting.Property.NodeScope);
    public static final Setting<TimeValue> DELETE_TIMEOUT = Setting.timeSetting("xpack.security.authc.api_key.delete.timeout",
            TimeValue.MINUS_ONE, Property.NodeScope);
    public static final Setting<TimeValue> DELETE_INTERVAL = Setting.timeSetting("xpack.security.authc.api_key.delete.interval",
            TimeValue.timeValueHours(24L), Property.NodeScope);
    public static final Setting<String> CACHE_HASH_ALGO_SETTING = Setting.simpleString("xpack.security.authc.api_key.cache.hash_algo",
        "ssha256", Setting.Property.NodeScope);
    public static final Setting<TimeValue> CACHE_TTL_SETTING = Setting.timeSetting("xpack.security.authc.api_key.cache.ttl",
        TimeValue.timeValueHours(24L), Property.NodeScope);
    public static final Setting<Integer> CACHE_MAX_KEYS_SETTING = Setting.intSetting("xpack.security.authc.api_key.cache.max_keys",
        10000, Property.NodeScope);

    private static final long API_KEY_DOC_FETCHING_INTERVAL_IN_SECONDS = 300L;

    private final Clock clock;
    private final Client client;
    private final XPackLicenseState licenseState;
    private final SecurityIndexManager securityIndex;
    private final ClusterService clusterService;
    private final Hasher hasher;
    private final boolean enabled;
    private final Settings settings;
    private final ExpiredApiKeysRemover expiredApiKeysRemover;
    private final TimeValue deleteInterval;
    private final Cache<String, ListenableFuture<CachedApiKeyHashResult>> apiKeyAuthCache;
    private final Hasher cacheHasher;
    private final ThreadPool threadPool;
    private final Cache<String, BytesReference> roleDescriptorsBytesCache;

    private volatile long lastExpirationRunMs;

    public ApiKeyService(Settings settings, Clock clock, Client client, XPackLicenseState licenseState, SecurityIndexManager securityIndex,
                         ClusterService clusterService, ThreadPool threadPool) {
        this.clock = clock;
        this.client = client;
        this.licenseState = licenseState;
        this.securityIndex = securityIndex;
        this.clusterService = clusterService;
        this.enabled = XPackSettings.API_KEY_SERVICE_ENABLED_SETTING.get(settings);
        this.hasher = Hasher.resolve(PASSWORD_HASHING_ALGORITHM.get(settings));
        this.settings = settings;
        this.deleteInterval = DELETE_INTERVAL.get(settings);
        this.expiredApiKeysRemover = new ExpiredApiKeysRemover(settings, client);
        this.threadPool = threadPool;
        this.cacheHasher = Hasher.resolve(CACHE_HASH_ALGO_SETTING.get(settings));
        final TimeValue ttl = CACHE_TTL_SETTING.get(settings);
        if (ttl.getNanos() > 0) {
            final Integer maximumWeight = CACHE_MAX_KEYS_SETTING.get(settings);
            this.apiKeyAuthCache = CacheBuilder.<String, ListenableFuture<CachedApiKeyHashResult>>builder()
                .setExpireAfterWrite(ttl)
                .setMaximumWeight(maximumWeight)
                .build();
            this.roleDescriptorsBytesCache = CacheBuilder.<String, BytesReference>builder()
                .setExpireAfterAccess(ttl)  // this uses access
                .setMaximumWeight(maximumWeight * 2)  // this is the theoretical upper bound
                .build();
        } else {
            this.apiKeyAuthCache = null;
            this.roleDescriptorsBytesCache = null;
        }
    }

    /**
     * Asynchronously creates a new API key based off of the request and authentication
     * @param authentication the authentication that this api key should be based off of
     * @param request the request to create the api key included any permission restrictions
     * @param userRoles the user's actual roles that we always enforce
     * @param listener the listener that will be used to notify of completion
     */
    public void createApiKey(Authentication authentication, CreateApiKeyRequest request, Set<RoleDescriptor> userRoles,
                             ActionListener<CreateApiKeyResponse> listener) {
        ensureEnabled();
        if (authentication == null) {
            listener.onFailure(new IllegalArgumentException("authentication must be provided"));
        } else {
            createApiKeyAndIndexIt(authentication, request, userRoles, listener);
        }
    }

    private void createApiKeyAndIndexIt(Authentication authentication, CreateApiKeyRequest request, Set<RoleDescriptor> roleDescriptorSet,
                                        ActionListener<CreateApiKeyResponse> listener) {
        final Instant created = clock.instant();
        final Instant expiration = getApiKeyExpiration(created, request);
        final SecureString apiKey = UUIDs.randomBase64UUIDSecureString();
        final Version version = clusterService.state().nodes().getMinNodeVersion();

        try (XContentBuilder builder = newDocument(apiKey, request.getName(), authentication, roleDescriptorSet, created, expiration,
            request.getRoleDescriptors(), version)) {

            final IndexRequest indexRequest =
                client.prepareIndex(SECURITY_MAIN_ALIAS)
                    .setSource(builder)
                    .setRefreshPolicy(request.getRefreshPolicy())
                    .request();
            final BulkRequest bulkRequest = toSingleItemBulkRequest(indexRequest);

            securityIndex.prepareIndexIfNeededThenExecute(listener::onFailure, () ->
                executeAsyncWithOrigin(client, SECURITY_ORIGIN, BulkAction.INSTANCE, bulkRequest,
                    TransportSingleItemBulkWriteAction.<IndexResponse>wrapBulkResponse(ActionListener.wrap(
                        indexResponse -> listener.onResponse(
                            new CreateApiKeyResponse(request.getName(), indexResponse.getId(), apiKey, expiration)),
                        listener::onFailure))));
        } catch (IOException e) {
            listener.onFailure(e);
        }
    }

    /**
     * package-private for testing
     */
    XContentBuilder newDocument(SecureString apiKey, String name, Authentication authentication, Set<RoleDescriptor> userRoles,
                                        Instant created, Instant expiration, List<RoleDescriptor> keyRoles,
                                        Version version) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject()
            .field("doc_type", "api_key")
            .field("creation_time", created.toEpochMilli())
            .field("expiration_time", expiration == null ? null : expiration.toEpochMilli())
            .field("api_key_invalidated", false);

        byte[] utf8Bytes = null;
        final char[] keyHash = hasher.hash(apiKey);
        try {
            utf8Bytes = CharArrays.toUtf8Bytes(keyHash);
            builder.field("api_key_hash").utf8Value(utf8Bytes, 0, utf8Bytes.length);
        } finally {
            if (utf8Bytes != null) {
                Arrays.fill(utf8Bytes, (byte) 0);
            }
            Arrays.fill(keyHash, (char) 0);
        }


        // Save role_descriptors
        builder.startObject("role_descriptors");
        if (keyRoles != null && keyRoles.isEmpty() == false) {
            for (RoleDescriptor descriptor : keyRoles) {
                builder.field(descriptor.getName(),
                    (contentBuilder, params) -> descriptor.toXContent(contentBuilder, params, true));
            }
        }
        builder.endObject();

        // Save limited_by_role_descriptors
        builder.startObject("limited_by_role_descriptors");
        for (RoleDescriptor descriptor : userRoles) {
            builder.field(descriptor.getName(),
                (contentBuilder, params) -> descriptor.toXContent(contentBuilder, params, true));
        }
        builder.endObject();

        builder.field("name", name)
            .field("version", version.id)
            .startObject("creator")
            .field("principal", authentication.getUser().principal())
            .field("metadata", authentication.getUser().metadata())
            .field("realm", authentication.getSourceRealm().getName())
            .field("realm_type", authentication.getSourceRealm().getType())
            .endObject()
            .endObject();

        return builder;
    }

    /**
     * Checks for the presence of a {@code Authorization} header with a value that starts with
     * {@code ApiKey }. If found this will attempt to authenticate the key.
     */
    void authenticateWithApiKeyIfPresent(ThreadContext ctx, ActionListener<AuthenticationResult> listener) {
        if (isEnabled()) {
            final ApiKeyCredentials credentials;
            try {
                credentials = getCredentialsFromHeader(ctx);
            } catch (IllegalArgumentException iae) {
                listener.onResponse(AuthenticationResult.unsuccessful(iae.getMessage(), iae));
                return;
            }

            if (credentials != null) {
                validateApiKeyCredentials(ctx, credentials, null, ActionListener.wrap(
                    response -> {
                        credentials.close();
                        listener.onResponse(response);
                    },
                    e -> {
                        credentials.close();
                        listener.onFailure(e);
                    }
                ));
            } else {
                listener.onResponse(AuthenticationResult.notHandled());
            }
        } else {
            listener.onResponse(AuthenticationResult.notHandled());
        }
    }

    public Authentication createApiKeyAuthentication(AuthenticationResult authResult, String nodeName) {
        if (false == authResult.isAuthenticated()) {
            throw new IllegalArgumentException("API Key authn result must be successful");
        }
        final User user = authResult.getUser();
        final RealmRef authenticatedBy = new RealmRef(ApiKeyService.API_KEY_REALM_NAME, ApiKeyService.API_KEY_REALM_TYPE, nodeName);
        return new Authentication(user, authenticatedBy, null, Version.CURRENT, Authentication.AuthenticationType.API_KEY,
                authResult.getMetadata());
    }

    /**
     * This method is kept for BWC and should only be used for authentication objects created before v7.9.0.
     * For authentication of newer versions, use {@link #getApiKeyIdAndRoleBytes}
     *
     * The current request has been authenticated by an API key and this method enables the
     * retrieval of role descriptors that are associated with the api key
     */
    public void getRoleForApiKey(Authentication authentication, ActionListener<ApiKeyRoleDescriptors> listener) {
        if (authentication.getAuthenticationType() != AuthenticationType.API_KEY) {
            throw new IllegalStateException("authentication type must be api key but is " + authentication.getAuthenticationType());
        }
        assert authentication.getVersion()
            .before(VERSION_API_KEY_ROLES_AS_BYTES) : "This method only applies to authentication objects created before v7.9.0";

        final Map<String, Object> metadata = authentication.getMetadata();
        final String apiKeyId = (String) metadata.get(API_KEY_ID_KEY);
        final Map<String, Object> roleDescriptors = (Map<String, Object>) metadata.get(API_KEY_ROLE_DESCRIPTORS_KEY);
        final Map<String, Object> authnRoleDescriptors = (Map<String, Object>) metadata.get(API_KEY_LIMITED_ROLE_DESCRIPTORS_KEY);

        if (roleDescriptors == null && authnRoleDescriptors == null) {
            listener.onFailure(new ElasticsearchSecurityException("no role descriptors found for API key"));
        } else if (roleDescriptors == null || roleDescriptors.isEmpty()) {
            final List<RoleDescriptor> authnRoleDescriptorsList = parseRoleDescriptors(apiKeyId, authnRoleDescriptors);
            listener.onResponse(new ApiKeyRoleDescriptors(apiKeyId, authnRoleDescriptorsList, null));
        } else {
            final List<RoleDescriptor> roleDescriptorList = parseRoleDescriptors(apiKeyId, roleDescriptors);
            final List<RoleDescriptor> authnRoleDescriptorsList = parseRoleDescriptors(apiKeyId, authnRoleDescriptors);
            listener.onResponse(new ApiKeyRoleDescriptors(apiKeyId, roleDescriptorList, authnRoleDescriptorsList));
        }
    }

    public Tuple<String, BytesReference> getApiKeyIdAndRoleBytes(Authentication authentication, boolean limitedBy) {
        if (authentication.getAuthenticationType() != AuthenticationType.API_KEY) {
            throw new IllegalStateException("authentication type must be api key but is " + authentication.getAuthenticationType());
        }
        assert authentication.getVersion()
            .onOrAfter(VERSION_API_KEY_ROLES_AS_BYTES) : "This method only applies to authentication objects created on or after v7.9.0";

        final Map<String, Object> metadata = authentication.getMetadata();
        return new Tuple<>(
            (String) metadata.get(API_KEY_ID_KEY),
            (BytesReference) metadata.get(limitedBy ? API_KEY_LIMITED_ROLE_DESCRIPTORS_KEY : API_KEY_ROLE_DESCRIPTORS_KEY));
    }

    public static class ApiKeyRoleDescriptors {

        private final String apiKeyId;
        private final List<RoleDescriptor> roleDescriptors;
        private final List<RoleDescriptor> limitedByRoleDescriptors;

        public ApiKeyRoleDescriptors(String apiKeyId, List<RoleDescriptor> roleDescriptors, List<RoleDescriptor> limitedByDescriptors) {
            this.apiKeyId = apiKeyId;
            this.roleDescriptors = roleDescriptors;
            this.limitedByRoleDescriptors = limitedByDescriptors;
        }

        public String getApiKeyId() {
            return apiKeyId;
        }

        public List<RoleDescriptor> getRoleDescriptors() {
            return roleDescriptors;
        }

        public List<RoleDescriptor> getLimitedByRoleDescriptors() {
            return limitedByRoleDescriptors;
        }
    }

    private List<RoleDescriptor> parseRoleDescriptors(final String apiKeyId, final Map<String, Object> roleDescriptors) {
        if (roleDescriptors == null) {
            return null;
        }
        return roleDescriptors.entrySet().stream()
            .map(entry -> {
                final String name = entry.getKey();
                final Map<String, Object> rdMap = (Map<String, Object>) entry.getValue();
                try (XContentBuilder builder = XContentBuilder.builder(XContentType.JSON.xContent())) {
                    builder.map(rdMap);
                    try (XContentParser parser = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY,
                        new ApiKeyLoggingDeprecationHandler(deprecationLogger, apiKeyId),
                        BytesReference.bytes(builder).streamInput())) {
                        return RoleDescriptor.parse(name, parser, false);
                    }
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }).collect(Collectors.toList());
    }

    public List<RoleDescriptor> parseRoleDescriptors(final String apiKeyId, BytesReference bytesReference) {
        if (bytesReference == null) {
            return Collections.emptyList();
        }

        List<RoleDescriptor> roleDescriptors = new ArrayList<>();
        try (
            XContentParser parser = XContentHelper.createParser(
                NamedXContentRegistry.EMPTY,
                new ApiKeyLoggingDeprecationHandler(deprecationLogger, apiKeyId),
                bytesReference,
                XContentType.JSON)) {
            parser.nextToken(); // skip outer start object
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                parser.nextToken(); // role name
                String roleName = parser.currentName();
                roleDescriptors.add(RoleDescriptor.parse(roleName, parser, false));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return Collections.unmodifiableList(roleDescriptors);
    }

    void validateApiKeyCredentials(ThreadContext ctx, ApiKeyCredentials credentials, ApiKeyDoc previouslyLoadedApiKeyDoc,
                                   ActionListener<AuthenticationResult> listener) {
        final String docId = credentials.getId();
        if (apiKeyAuthCache != null) {
            final AtomicBoolean valueAlreadyInCache = new AtomicBoolean(true);
            final ListenableFuture<CachedApiKeyHashResult> listenableCacheEntry;
            try {
                listenableCacheEntry = apiKeyAuthCache.computeIfAbsent(docId,
                    k -> {
                        valueAlreadyInCache.set(false);
                        return new ListenableFuture<>();
                    });
            } catch (ExecutionException e) {
                listener.onFailure(e);
                return;
            }

            if (valueAlreadyInCache.get()) {
                // Other thread is performing validation of the same key already
                validateWithCachedEntry(ctx, credentials, listenableCacheEntry, listener);
            } else {
                // This thread is performing authentication
                CheckedBiConsumer<ApiKeyDoc, Boolean, ExecutionException> cachingConsumer = (apiKeyDoc, verified) -> {
                    final CachedApiKeyHashResult cachedApiKey = apiKeyDocToCachedApiKeyHashResult(
                        apiKeyDoc, verified, credentials.getKey());
                    // Cache the descriptors first to best ensure descriptors can be found for a cached key
                    roleDescriptorsBytesCache.computeIfAbsent(cachedApiKey.roleDescriptorsHash,
                        k -> apiKeyDoc.roleDescriptorsBytes);
                    roleDescriptorsBytesCache.computeIfAbsent(cachedApiKey.limitedByRoleDescriptorsHash,
                        k -> apiKeyDoc.limitedByRoleDescriptorsBytes);
                    listenableCacheEntry.onResponse(cachedApiKey);
                };
                if (previouslyLoadedApiKeyDoc == null) {
                    // No previously loaded API key doc available, so we need load the API key document first
                    loadApiKeyDocAndValidate(ctx, credentials, cachingConsumer, listener);
                } else {
                    // The API key doc has been loaded in previous round, we can go straight to compare hashes
                    verifyKeyAgainstApiKeyDoc(docId, previouslyLoadedApiKeyDoc, credentials, cachingConsumer, listener);
                }
            }
        } else { // No cache is configured
            loadApiKeyDocAndValidate(ctx, credentials, null, listener);
        }
    }

    private void validateWithCachedEntry(ThreadContext ctx, ApiKeyCredentials credentials,
                                         ListenableFuture<CachedApiKeyHashResult> listenableCacheEntry,
                                         ActionListener<AuthenticationResult> listener) {

        listenableCacheEntry.addListener(ActionListener.wrap(cachedApiKeyHashResult -> {
            final long lastReloadedAt = cachedApiKeyHashResult.lastReloadedAt.get();
            final Instant nextReloadedAt = Instant.ofEpochMilli(lastReloadedAt).plusSeconds(API_KEY_DOC_FETCHING_INTERVAL_IN_SECONDS);

            if (cachedApiKeyHashResult.success) {
                if (cachedApiKeyHashResult.verify(credentials.getKey())) {
                    final ApiKeyDoc apiKeyDoc = cachedApiKeyHashResult.toApiKeyDoc();
                    if (apiKeyDoc != null) {
                        // Before we fully rely on this cached entry, check whether it needs to be reload.
                        if (clock.instant().isAfter(nextReloadedAt)) {
                            // If the entry needs to be reloaded, attempt to claim the reload by setting a
                            // new lastReloadedAt time.
                            if (cachedApiKeyHashResult.lastReloadedAt.compareAndSet(lastReloadedAt, clock.instant().toEpochMilli())) {
                                reloadApiKeyDocAndValidate(ctx, credentials, listenableCacheEntry, cachedApiKeyHashResult, listener);
                            } else {
                                // Some other thread has claimed the reload, proceed as if this is a new authentication.
                                validateApiKeyCredentials(ctx, credentials, null, listener);
                            }
                        } else {
                            validateApiKeyExpiration(apiKeyDoc, credentials, clock, listener);
                        }
                    } else {
                        // Since API key doc and role descriptors are stored in two separate caches,
                        // it might be possible (though extremely rare) that the key is found in cache
                        // while the role descriptors are invalidated. When this happens, we invalidate
                        // the key and start the auth again.
                        apiKeyAuthCache.invalidate(credentials.getId(), listenableCacheEntry);
                        validateApiKeyCredentials(ctx, credentials, null, listener);
                    }
                } else {
                    listener.onResponse(AuthenticationResult.unsuccessful("invalid credentials", null));
                }
            } else if (cachedApiKeyHashResult.verify(credentials.getKey())) { // same key, pass the same result
                listener.onResponse(AuthenticationResult.unsuccessful("invalid credentials", null));
            } else {
                // Invalidate the cache since it is a negative entry and we have a potential positive candidate
                apiKeyAuthCache.invalidate(credentials.getId(), listenableCacheEntry);
                // Re-enter the authentication flow, if the cached API key doc can be reused, we will reuse it
                // to avoid hitting the index. If it should be reload, no re-use is needed.
                if (clock.instant().isAfter(nextReloadedAt)) {
                    validateApiKeyCredentials(ctx, credentials, null, listener);
                } else {
                    validateApiKeyCredentials(ctx, credentials, cachedApiKeyHashResult.toApiKeyDoc(), listener);
                }
            }
        }, listener::onFailure), threadPool.generic(), threadPool.getThreadContext());
    }

    private void reloadApiKeyDocAndValidate(ThreadContext ctx, ApiKeyCredentials credentials,
                                            ListenableFuture<CachedApiKeyHashResult> listenableCacheEntry,
                                            CachedApiKeyHashResult existingCachedApiKeyAuthResult,
                                            ActionListener<AuthenticationResult> listener) {
        // The caching consumer checks whether the reloaded API key doc is the same as the cached one.
        // If they are not the same, invalidate the cache and create a new entry with the reloaded one
        final CheckedBiConsumer<ApiKeyDoc, Boolean, ExecutionException> cachingConsumer = (apiKeyDoc, verified) -> {
            final CachedApiKeyHashResult newCachedApiKeyAuthResult =
                apiKeyDocToCachedApiKeyHashResult(apiKeyDoc, verified, credentials.getKey());
            if (false == newCachedApiKeyAuthResult.equals(existingCachedApiKeyAuthResult)) {
                apiKeyAuthCache.invalidate(credentials.getId(), listenableCacheEntry);
                final ListenableFuture<CachedApiKeyHashResult> newEntry = new ListenableFuture<>();
                // TODO: this assumes computeIfAbsent returns the same object if the loader is called
                if (newEntry == apiKeyAuthCache.computeIfAbsent(credentials.getId(), k -> newEntry)) {
                    // Cache the descriptors first to ensure when the API key is available in the cache, the descriptors
                    // are also available
                    roleDescriptorsBytesCache.computeIfAbsent(newCachedApiKeyAuthResult.roleDescriptorsHash,
                        k -> apiKeyDoc.roleDescriptorsBytes);
                    roleDescriptorsBytesCache.computeIfAbsent(newCachedApiKeyAuthResult.limitedByRoleDescriptorsHash,
                        k -> apiKeyDoc.limitedByRoleDescriptorsBytes);
                    newEntry.onResponse(newCachedApiKeyAuthResult);
                }
            }
        };
        loadApiKeyDocAndValidate(ctx, credentials, cachingConsumer, listener);
    }

    /**
     * Load the API key document and validate the credentials against it. The API key document and the
     * authentication result may be cached if the cachingConsumer is not null.
     *
     * @param cachingConsumer The consumer that implements the caching behaviour for the API key document
     *                        and authentication result. Can be null if no caching is configured.
     */
    private void loadApiKeyDocAndValidate(ThreadContext ctx, ApiKeyCredentials credentials,
                                  @Nullable CheckedBiConsumer<ApiKeyDoc, Boolean, ExecutionException> cachingConsumer,
                                  ActionListener<AuthenticationResult> listener) {
        final String docId = credentials.getId();
        final GetRequest getRequest = client
            .prepareGet(SECURITY_MAIN_ALIAS, docId)
            .setFetchSource(true)
            .request();
        executeAsyncWithOrigin(ctx, SECURITY_ORIGIN, getRequest, ActionListener.<GetResponse>wrap(response -> {
                if (response.isExists()) {
                    final ApiKeyDoc apiKeyDoc;
                    try (XContentParser parser = XContentHelper.createParser(
                        NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE,
                        response.getSourceAsBytesRef(), XContentType.JSON)) {
                        apiKeyDoc = ApiKeyDoc.fromXContent(parser);
                    }
                    verifyKeyAgainstApiKeyDoc(docId, apiKeyDoc, credentials, cachingConsumer, listener);
                } else {
                    listener.onResponse(
                        AuthenticationResult.unsuccessful("unable to find apikey with id " + credentials.getId(), null));
                }
            },
            e -> {
                if (ExceptionsHelper.unwrapCause(e) instanceof EsRejectedExecutionException) {
                    listener.onResponse(AuthenticationResult.terminate("server is too busy to respond", e));
                } else {
                    listener.onResponse(AuthenticationResult.unsuccessful(
                        "apikey authentication for id " + credentials.getId() + " encountered a failure",e));
                }
            }),
            client::get);
    }

    private void verifyKeyAgainstApiKeyDoc(String docId, ApiKeyDoc apiKeyDoc, ApiKeyCredentials credentials,
                                           @Nullable CheckedBiConsumer<ApiKeyDoc, Boolean, ExecutionException> cachingConsumer,
                                           ActionListener<AuthenticationResult> listener) {
        if ("api_key".equals(apiKeyDoc.docType) == false) {
            listener.onResponse(
                AuthenticationResult.unsuccessful("document [" + docId + "] is [" + apiKeyDoc.docType + "] not an api key", null));
        } else if (apiKeyDoc.invalidated == null) {
            listener.onResponse(AuthenticationResult.unsuccessful("api key document is missing invalidated field", null));
        } else if (apiKeyDoc.invalidated) {
            listener.onResponse(AuthenticationResult.unsuccessful("api key has been invalidated", null));
        } else {
            if (apiKeyDoc.hash == null) {
                throw new IllegalStateException("api key hash is missing");
            }

            verifyKeyAgainstHash(apiKeyDoc.hash, credentials, ActionListener.wrap(
                verified -> {
                    if (cachingConsumer != null) {
                        cachingConsumer.accept(apiKeyDoc, verified);
                    }
                    if (verified) {
                        // move on
                        validateApiKeyExpiration(apiKeyDoc, credentials, clock, listener);
                    } else {
                        listener.onResponse(AuthenticationResult.unsuccessful("invalid credentials", null));
                    }
                }, listener::onFailure
            ));
        }
    }

    // pkg private for testing
    CachedApiKeyHashResult getFromCache(String id) {
        return apiKeyAuthCache == null ? null : FutureUtils.get(apiKeyAuthCache.get(id), 0L, TimeUnit.MILLISECONDS);
    }

    // package-private for testing
    void validateApiKeyExpiration(ApiKeyDoc apiKeyDoc, ApiKeyCredentials credentials, Clock clock,
                                  ActionListener<AuthenticationResult> listener) {
        if (apiKeyDoc.expirationTime == -1 || Instant.ofEpochMilli(apiKeyDoc.expirationTime).isAfter(clock.instant())) {
            final String principal = Objects.requireNonNull((String) apiKeyDoc.creator.get("principal"));
            Map<String, Object> metadata = (Map<String, Object>) apiKeyDoc.creator.get("metadata");
            final User apiKeyUser = new User(principal, Strings.EMPTY_ARRAY, null, null, metadata, true);
            final Map<String, Object> authResultMetadata = new HashMap<>();
            authResultMetadata.put(API_KEY_CREATOR_REALM_NAME, apiKeyDoc.creator.get("realm"));
            authResultMetadata.put(API_KEY_CREATOR_REALM_TYPE, apiKeyDoc.creator.get("realm_type"));
            authResultMetadata.put(API_KEY_ROLE_DESCRIPTORS_KEY, apiKeyDoc.roleDescriptorsBytes);
            authResultMetadata.put(API_KEY_LIMITED_ROLE_DESCRIPTORS_KEY, apiKeyDoc.limitedByRoleDescriptorsBytes);
            authResultMetadata.put(API_KEY_ID_KEY, credentials.getId());
            authResultMetadata.put(API_KEY_NAME_KEY, apiKeyDoc.name);
            listener.onResponse(AuthenticationResult.success(apiKeyUser, authResultMetadata));
        } else {
            listener.onResponse(AuthenticationResult.unsuccessful("api key is expired", null));
        }
    }

    /**
     * Gets the API Key from the <code>Authorization</code> header if the header begins with
     * <code>ApiKey </code>
     */
    static ApiKeyCredentials getCredentialsFromHeader(ThreadContext threadContext) {
        String header = threadContext.getHeader("Authorization");
        if (Strings.hasText(header) && header.regionMatches(true, 0, "ApiKey ", 0, "ApiKey ".length())
            && header.length() > "ApiKey ".length()) {
            final byte[] decodedApiKeyCredBytes = Base64.getDecoder().decode(header.substring("ApiKey ".length()));
            char[] apiKeyCredChars = null;
            try {
                apiKeyCredChars = CharArrays.utf8BytesToChars(decodedApiKeyCredBytes);
                int colonIndex = -1;
                for (int i = 0; i < apiKeyCredChars.length; i++) {
                    if (apiKeyCredChars[i] == ':') {
                        colonIndex = i;
                        break;
                    }
                }

                if (colonIndex < 1) {
                    throw new IllegalArgumentException("invalid ApiKey value");
                }
                return new ApiKeyCredentials(new String(Arrays.copyOfRange(apiKeyCredChars, 0, colonIndex)),
                    new SecureString(Arrays.copyOfRange(apiKeyCredChars, colonIndex + 1, apiKeyCredChars.length)));
            } finally {
                if (apiKeyCredChars != null) {
                    Arrays.fill(apiKeyCredChars, (char) 0);
                }
            }
        }
        return null;
    }

    // Protected instance method so this can be mocked
    protected void verifyKeyAgainstHash(String apiKeyHash, ApiKeyCredentials credentials, ActionListener<Boolean> listener) {
        threadPool.executor(SECURITY_CRYPTO_THREAD_POOL_NAME).execute(ActionRunnable.supply(listener, () -> {
            Hasher hasher = Hasher.resolveFromHash(apiKeyHash.toCharArray());
            final char[] apiKeyHashChars = apiKeyHash.toCharArray();
            try {
                return hasher.verify(credentials.getKey(), apiKeyHashChars);
            } finally {
                Arrays.fill(apiKeyHashChars, (char) 0);
            }
        }));
    }

    private Instant getApiKeyExpiration(Instant now, CreateApiKeyRequest request) {
        if (request.getExpiration() != null) {
            return now.plusSeconds(request.getExpiration().getSeconds());
        } else {
            return null;
        }
    }

    private boolean isEnabled() {
        return enabled && licenseState.isSecurityEnabled() &&
            licenseState.checkFeature(XPackLicenseState.Feature.SECURITY_API_KEY_SERVICE);
    }

    public void ensureEnabled() {
        if (licenseState.isSecurityEnabled() == false ||
            licenseState.checkFeature(XPackLicenseState.Feature.SECURITY_API_KEY_SERVICE) == false) {
            throw LicenseUtils.newComplianceException("api keys");
        }
        if (enabled == false) {
            throw new FeatureNotEnabledException(Feature.API_KEY_SERVICE, "api keys are not enabled");
        }
    }

    // public class for testing
    public static final class ApiKeyCredentials implements Closeable {
        private final String id;
        private final SecureString key;

        public ApiKeyCredentials(String id, SecureString key) {
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
    }

    private static class ApiKeyLoggingDeprecationHandler implements DeprecationHandler {

        private final DeprecationLogger deprecationLogger;
        private final String apiKeyId;

        private ApiKeyLoggingDeprecationHandler(DeprecationLogger logger, String apiKeyId) {
            this.deprecationLogger = logger;
            this.apiKeyId = apiKeyId;
        }

        @Override
        public void usedDeprecatedName(String parserName, Supplier<XContentLocation> location, String usedName, String modernName) {
            String prefix = parserName == null ? "" : "[" + parserName + "][" + location.get() + "] ";
            deprecationLogger.deprecate("api_key_field",
                "{}Deprecated field [{}] used in api key [{}], expected [{}] instead", prefix, usedName, apiKeyId, modernName);
        }

        @Override
        public void usedDeprecatedField(String parserName, Supplier<XContentLocation> location, String usedName, String replacedWith) {
            String prefix = parserName == null ? "" : "[" + parserName + "][" + location.get() + "] ";
            deprecationLogger.deprecate("api_key_field",
                "{}Deprecated field [{}] used in api key [{}], replaced by [{}]", prefix, usedName, apiKeyId, replacedWith);
        }

        @Override
        public void usedDeprecatedField(String parserName, Supplier<XContentLocation> location, String usedName) {
            String prefix = parserName == null ? "" : "[" + parserName + "][" + location.get() + "] ";
            deprecationLogger.deprecate("api_key_field",
                "{}Deprecated field [{}] used in api key [{}], which is unused and will be removed entirely", prefix, usedName, apiKeyId);
        }
    }

    /**
     * Invalidate API keys for given realm, user name, API key name and id.
     * @param realmName realm name
     * @param username user name
     * @param apiKeyName API key name
     * @param apiKeyId API key id
     * @param invalidateListener listener for {@link InvalidateApiKeyResponse}
     */
    public void invalidateApiKeys(String realmName, String username, String apiKeyName, String apiKeyId,
                                  ActionListener<InvalidateApiKeyResponse> invalidateListener) {
        ensureEnabled();
        if (Strings.hasText(realmName) == false && Strings.hasText(username) == false && Strings.hasText(apiKeyName) == false
            && Strings.hasText(apiKeyId) == false) {
            logger.trace("none of the parameters [api key id, api key name, username, realm name] were specified for invalidation");
            invalidateListener
                .onFailure(new IllegalArgumentException("One of [api key id, api key name, username, realm name] must be specified"));
        } else {
            findApiKeysForUserRealmApiKeyIdAndNameCombination(realmName, username, apiKeyName, apiKeyId, true, false,
                ActionListener.wrap(apiKeys -> {
                    if (apiKeys.isEmpty()) {
                        logger.debug(
                            "No active api keys to invalidate for realm [{}], username [{}], api key name [{}] and api key id [{}]",
                            realmName, username, apiKeyName, apiKeyId);
                        invalidateListener.onResponse(InvalidateApiKeyResponse.emptyResponse());
                    } else {
                        invalidateAllApiKeys(apiKeys.stream().map(apiKey -> apiKey.getId()).collect(Collectors.toSet()),
                            invalidateListener);
                    }
                }, invalidateListener::onFailure));
        }
    }

    private void invalidateAllApiKeys(Collection<String> apiKeyIds, ActionListener<InvalidateApiKeyResponse> invalidateListener) {
        indexInvalidation(apiKeyIds, invalidateListener, null);
    }

    private void findApiKeys(final BoolQueryBuilder boolQuery, boolean filterOutInvalidatedKeys, boolean filterOutExpiredKeys,
                             ActionListener<Collection<ApiKey>> listener) {
        if (filterOutInvalidatedKeys) {
            boolQuery.filter(QueryBuilders.termQuery("api_key_invalidated", false));
        }
        if (filterOutExpiredKeys) {
            final BoolQueryBuilder expiredQuery = QueryBuilders.boolQuery();
            expiredQuery.should(QueryBuilders.rangeQuery("expiration_time").lte(Instant.now().toEpochMilli()));
            expiredQuery.should(QueryBuilders.boolQuery().mustNot(QueryBuilders.existsQuery("expiration_time")));
            boolQuery.filter(expiredQuery);
        }
        final Supplier<ThreadContext.StoredContext> supplier = client.threadPool().getThreadContext().newRestorableContext(false);
        try (ThreadContext.StoredContext ignore = client.threadPool().getThreadContext().stashWithOrigin(SECURITY_ORIGIN)) {
            final SearchRequest request = client.prepareSearch(SECURITY_MAIN_ALIAS)
                    .setScroll(DEFAULT_KEEPALIVE_SETTING.get(settings))
                    .setQuery(boolQuery)
                    .setVersion(false)
                    .setSize(1000)
                    .setFetchSource(true)
                    .request();
            securityIndex.checkIndexVersionThenExecute(listener::onFailure,
                    () -> ScrollHelper.fetchAllByEntity(client, request, new ContextPreservingActionListener<>(supplier, listener),
                            (SearchHit hit) -> {
                                Map<String, Object> source = hit.getSourceAsMap();
                                String name = (String) source.get("name");
                                String id = hit.getId();
                                Long creation = (Long) source.get("creation_time");
                                Long expiration = (Long) source.get("expiration_time");
                                Boolean invalidated = (Boolean) source.get("api_key_invalidated");
                                String username = (String) ((Map<String, Object>) source.get("creator")).get("principal");
                                String realm = (String) ((Map<String, Object>) source.get("creator")).get("realm");
                                return new ApiKey(name, id, Instant.ofEpochMilli(creation),
                                        (expiration != null) ? Instant.ofEpochMilli(expiration) : null, invalidated, username, realm);
                            }));
        }
    }

    private void findApiKeysForUserRealmApiKeyIdAndNameCombination(String realmName, String userName, String apiKeyName, String apiKeyId,
                                                                   boolean filterOutInvalidatedKeys, boolean filterOutExpiredKeys,
                                                                   ActionListener<Collection<ApiKey>> listener) {
        final SecurityIndexManager frozenSecurityIndex = securityIndex.freeze();
        if (frozenSecurityIndex.indexExists() == false) {
            listener.onResponse(Collections.emptyList());
        } else if (frozenSecurityIndex.isAvailable() == false) {
            listener.onFailure(frozenSecurityIndex.getUnavailableReason());
        } else {
            final BoolQueryBuilder boolQuery = QueryBuilders.boolQuery().filter(QueryBuilders.termQuery("doc_type", "api_key"));
            if (Strings.hasText(realmName)) {
                boolQuery.filter(QueryBuilders.termQuery("creator.realm", realmName));
            }
            if (Strings.hasText(userName)) {
                boolQuery.filter(QueryBuilders.termQuery("creator.principal", userName));
            }
            if (Strings.hasText(apiKeyName) && "*".equals(apiKeyName) == false) {
                if (apiKeyName.endsWith("*")) {
                    boolQuery.filter(QueryBuilders.prefixQuery("name", apiKeyName.substring(0, apiKeyName.length() - 1)));
                } else {
                    boolQuery.filter(QueryBuilders.termQuery("name", apiKeyName));
                }
            }
            if (Strings.hasText(apiKeyId)) {
                boolQuery.filter(QueryBuilders.termQuery("_id", apiKeyId));
            }

            findApiKeys(boolQuery, filterOutInvalidatedKeys, filterOutExpiredKeys, listener);
        }
    }

    /**
     * Performs the actual invalidation of a collection of api keys
     *
     * @param apiKeyIds       the api keys to invalidate
     * @param listener        the listener to notify upon completion
     * @param previousResult  if this not the initial attempt for invalidation, it contains the result of invalidating
     *                        api keys up to the point of the retry. This result is added to the result of the current attempt
     */
    private void indexInvalidation(Collection<String> apiKeyIds, ActionListener<InvalidateApiKeyResponse> listener,
                                   @Nullable InvalidateApiKeyResponse previousResult) {
        maybeStartApiKeyRemover();
        if (apiKeyIds.isEmpty()) {
            listener.onFailure(new ElasticsearchSecurityException("No api key ids provided for invalidation"));
        } else {
            BulkRequestBuilder bulkRequestBuilder = client.prepareBulk();
            for (String apiKeyId : apiKeyIds) {
                UpdateRequest request = client
                    .prepareUpdate(SECURITY_MAIN_ALIAS, apiKeyId)
                    .setDoc(Collections.singletonMap("api_key_invalidated", true))
                    .request();
                bulkRequestBuilder.add(request);
            }
            bulkRequestBuilder.setRefreshPolicy(RefreshPolicy.WAIT_UNTIL);
            securityIndex.prepareIndexIfNeededThenExecute(ex -> listener.onFailure(traceLog("prepare security index", ex)),
                () -> executeAsyncWithOrigin(client.threadPool().getThreadContext(), SECURITY_ORIGIN, bulkRequestBuilder.request(),
                    ActionListener.<BulkResponse>wrap(bulkResponse -> {
                        ArrayList<ElasticsearchException> failedRequestResponses = new ArrayList<>();
                        ArrayList<String> previouslyInvalidated = new ArrayList<>();
                        ArrayList<String> invalidated = new ArrayList<>();
                        if (null != previousResult) {
                            failedRequestResponses.addAll((previousResult.getErrors()));
                            previouslyInvalidated.addAll(previousResult.getPreviouslyInvalidatedApiKeys());
                            invalidated.addAll(previousResult.getInvalidatedApiKeys());
                        }
                        for (BulkItemResponse bulkItemResponse : bulkResponse.getItems()) {
                            if (bulkItemResponse.isFailed()) {
                                Throwable cause = bulkItemResponse.getFailure().getCause();
                                final String failedApiKeyId = bulkItemResponse.getFailure().getId();
                                traceLog("invalidate api key", failedApiKeyId, cause);
                                failedRequestResponses.add(new ElasticsearchException("Error invalidating api key", cause));
                            } else {
                                UpdateResponse updateResponse = bulkItemResponse.getResponse();
                                if (updateResponse.getResult() == DocWriteResponse.Result.UPDATED) {
                                    logger.debug("Invalidated api key for doc [{}]", updateResponse.getId());
                                    invalidated.add(updateResponse.getId());
                                } else if (updateResponse.getResult() == DocWriteResponse.Result.NOOP) {
                                    previouslyInvalidated.add(updateResponse.getId());
                                }
                            }
                        }
                        InvalidateApiKeyResponse result = new InvalidateApiKeyResponse(invalidated, previouslyInvalidated,
                            failedRequestResponses);
                        listener.onResponse(result);
                    }, e -> {
                        Throwable cause = ExceptionsHelper.unwrapCause(e);
                        traceLog("invalidate api keys", cause);
                        listener.onFailure(e);
                    }), client::bulk));
        }
    }

    /**
     * Logs an exception concerning a specific api key at TRACE level (if enabled)
     */
    private <E extends Throwable> E traceLog(String action, String identifier, E exception) {
        if (logger.isTraceEnabled()) {
            if (exception instanceof ElasticsearchException) {
                final ElasticsearchException esEx = (ElasticsearchException) exception;
                final Object detail = esEx.getHeader("error_description");
                if (detail != null) {
                    logger.trace(() -> new ParameterizedMessage("Failure in [{}] for id [{}] - [{}]", action, identifier, detail),
                        esEx);
                } else {
                    logger.trace(() -> new ParameterizedMessage("Failure in [{}] for id [{}]", action, identifier),
                        esEx);
                }
            } else {
                logger.trace(() -> new ParameterizedMessage("Failure in [{}] for id [{}]", action, identifier), exception);
            }
        }
        return exception;
    }

    /**
     * Logs an exception at TRACE level (if enabled)
     */
    private <E extends Throwable> E traceLog(String action, E exception) {
        if (logger.isTraceEnabled()) {
            if (exception instanceof ElasticsearchException) {
                final ElasticsearchException esEx = (ElasticsearchException) exception;
                final Object detail = esEx.getHeader("error_description");
                if (detail != null) {
                    logger.trace(() -> new ParameterizedMessage("Failure in [{}] - [{}]", action, detail), esEx);
                } else {
                    logger.trace(() -> new ParameterizedMessage("Failure in [{}]", action), esEx);
                }
            } else {
                logger.trace(() -> new ParameterizedMessage("Failure in [{}]", action), exception);
            }
        }
        return exception;
    }

    // pkg scoped for testing
    boolean isExpirationInProgress() {
        return expiredApiKeysRemover.isExpirationInProgress();
    }

    // pkg scoped for testing
    long lastTimeWhenApiKeysRemoverWasTriggered() {
        return lastExpirationRunMs;
    }

    private void maybeStartApiKeyRemover() {
        if (securityIndex.isAvailable()) {
            if (client.threadPool().relativeTimeInMillis() - lastExpirationRunMs > deleteInterval.getMillis()) {
                expiredApiKeysRemover.submit(client.threadPool());
                lastExpirationRunMs = client.threadPool().relativeTimeInMillis();
            }
        }
    }

    /**
     * Get API key information for given realm, user, API key name and id combination
     * @param realmName realm name
     * @param username user name
     * @param apiKeyName API key name
     * @param apiKeyId API key id
     * @param listener listener for {@link GetApiKeyResponse}
     */
    public void getApiKeys(String realmName, String username, String apiKeyName, String apiKeyId,
                           ActionListener<GetApiKeyResponse> listener) {
        ensureEnabled();
        findApiKeysForUserRealmApiKeyIdAndNameCombination(realmName, username, apiKeyName, apiKeyId, false, false,
            ActionListener.wrap(apiKeyInfos -> {
                if (apiKeyInfos.isEmpty()) {
                    logger.debug("No active api keys found for realm [{}], user [{}], api key name [{}] and api key id [{}]",
                        realmName, username, apiKeyName, apiKeyId);
                    listener.onResponse(GetApiKeyResponse.emptyResponse());
                } else {
                    listener.onResponse(new GetApiKeyResponse(apiKeyInfos));
                }
            }, listener::onFailure));
    }

    /**
     * Returns realm name for the authenticated user.
     * If the user is authenticated by realm type {@value API_KEY_REALM_TYPE}
     * then it will return the realm name of user who created this API key.
     * @param authentication {@link Authentication}
     * @return realm name
     */
    public static String getCreatorRealmName(final Authentication authentication) {
        if (AuthenticationType.API_KEY == authentication.getAuthenticationType()) {
            return (String) authentication.getMetadata().get(API_KEY_CREATOR_REALM_NAME);
        } else {
            return authentication.getSourceRealm().getName();
        }
    }

    /**
     * Returns realm type for the authenticated user.
     * If the user is authenticated by realm type {@value API_KEY_REALM_TYPE}
     * then it will return the realm name of user who created this API key.
     * @param authentication {@link Authentication}
     * @return realm type
     */
    public static String getCreatorRealmType(final Authentication authentication) {
        if (AuthenticationType.API_KEY == authentication.getAuthenticationType()) {
            return (String) authentication.getMetadata().get(API_KEY_CREATOR_REALM_TYPE);
        } else {
            return authentication.getSourceRealm().getType();
        }
    }

    final class CachedApiKeyHashResult {
        final long creationTime;
        final long expirationTime;
        final boolean invalidated;
        final String hash;
        final String name;
        final int version;
        final Map<String, Object> creator;
        final String roleDescriptorsHash;
        final String limitedByRoleDescriptorsHash;
        final boolean success;
        final char[] inMemHash;
        final AtomicLong lastReloadedAt = new AtomicLong();

        CachedApiKeyHashResult(
            long creationTime,
            long expirationTime,
            boolean invalidated,
            String hash,
            String name,
            int version,
            Map<String, Object> creator,
            String roleDescriptorsHash,
            String limitedByRoleDescriptorsHash,
            boolean success,
            SecureString apiKey) {

            this.creationTime = creationTime;
            this.expirationTime = expirationTime;
            this.invalidated = invalidated;
            this.hash = hash;
            this.name = name;
            this.version = version;
            this.creator = creator;
            this.roleDescriptorsHash = roleDescriptorsHash;
            this.limitedByRoleDescriptorsHash = limitedByRoleDescriptorsHash;
            this.success = success;
            this.inMemHash = cacheHasher.hash(apiKey);
            this.lastReloadedAt.set(clock.instant().toEpochMilli());
        }

        private boolean verify(SecureString password) {
            return inMemHash != null && cacheHasher.verify(password, inMemHash);
        }

        ApiKeyDoc toApiKeyDoc() {
            final BytesReference roleDescriptorsBytes = roleDescriptorsBytesCache.get(roleDescriptorsHash);
            final BytesReference limitedByRoleDescriptorsBytes = roleDescriptorsBytesCache.get(limitedByRoleDescriptorsHash);
            if (roleDescriptorsBytes == null || limitedByRoleDescriptorsBytes == null) {
                return null;
            }
            return new ApiKeyDoc(
                "api_key",
                creationTime,
                expirationTime,
                invalidated,
                hash,
                name,
                version,
                roleDescriptorsBytes,
                limitedByRoleDescriptorsBytes,
                creator
            );
        }

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            CachedApiKeyHashResult that = (CachedApiKeyHashResult) o;
            return creationTime == that.creationTime && expirationTime == that.expirationTime
                && invalidated == that.invalidated && version == that.version && success == that.success
                && hash.equals(that.hash) && name.equals(that.name) && creator.equals(that.creator)
                && roleDescriptorsHash.equals(that.roleDescriptorsHash)
                && limitedByRoleDescriptorsHash.equals(that.limitedByRoleDescriptorsHash)
                && Arrays.equals(inMemHash, that.inMemHash);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(
                creationTime,
                expirationTime,
                invalidated,
                hash,
                name,
                version,
                creator,
                roleDescriptorsHash,
                limitedByRoleDescriptorsHash,
                success);
            result = 31 * result + Arrays.hashCode(inMemHash);
            return result;
        }
    }

    public static final class ApiKeyDoc {

        static final InstantiatingObjectParser<ApiKeyDoc, Void> PARSER;
        static {
            InstantiatingObjectParser.Builder<ApiKeyDoc, Void> builder =
                InstantiatingObjectParser.builder("api_key_doc", true, ApiKeyDoc.class);
            builder.declareString(constructorArg(), new ParseField("doc_type"));
            builder.declareLong(constructorArg(), new ParseField("creation_time"));
            builder.declareLongOrNull(constructorArg(), -1, new ParseField("expiration_time"));
            builder.declareBoolean(constructorArg(), new ParseField("api_key_invalidated"));
            builder.declareString(constructorArg(), new ParseField("api_key_hash"));
            builder.declareStringOrNull(optionalConstructorArg(), new ParseField("name"));
            builder.declareInt(constructorArg(), new ParseField("version"));
            ObjectParserHelper<ApiKeyDoc, Void> parserHelper = new ObjectParserHelper<>();
            parserHelper.declareRawObject(builder, constructorArg(), new ParseField("role_descriptors"));
            parserHelper.declareRawObject(builder, constructorArg(), new ParseField("limited_by_role_descriptors"));
            builder.declareObject(constructorArg(), (p, c) -> p.map(), new ParseField("creator"));
            PARSER = builder.build();
        }

        final String docType;
        final long creationTime;
        final long expirationTime;
        final Boolean invalidated;
        final String hash;
        @Nullable
        final String name;
        final int version;
        final BytesReference roleDescriptorsBytes;
        final BytesReference limitedByRoleDescriptorsBytes;
        final Map<String, Object> creator;

        public ApiKeyDoc(
            String docType,
            long creationTime,
            long expirationTime,
            Boolean invalidated,
            String hash,
            @Nullable String name,
            int version,
            BytesReference roleDescriptorsBytes,
            BytesReference limitedByRoleDescriptorsBytes,
            Map<String, Object> creator) {

            this.docType = docType;
            this.creationTime = creationTime;
            this.expirationTime = expirationTime;
            this.invalidated = invalidated;
            this.hash = hash;
            this.name = name;
            this.version = version;
            this.roleDescriptorsBytes = roleDescriptorsBytes;
            this.limitedByRoleDescriptorsBytes = limitedByRoleDescriptorsBytes;
            this.creator = creator;
        }

        static ApiKeyDoc fromXContent(XContentParser parser) {
            return PARSER.apply(parser, null);
        }

    }

    CachedApiKeyHashResult apiKeyDocToCachedApiKeyHashResult(ApiKeyDoc apiKeyDoc, boolean success, SecureString apiKey) {
        final MessageDigest digest = MessageDigests.sha256();
        digest.update(BytesReference.toBytes(apiKeyDoc.roleDescriptorsBytes));
        final String roleDescriptorsHash = MessageDigests.toHexString(digest.digest());
        digest.reset();
        digest.update(BytesReference.toBytes(apiKeyDoc.limitedByRoleDescriptorsBytes));
        final String limitedByRoleDescriptorsHash = MessageDigests.toHexString(digest.digest());

        return new CachedApiKeyHashResult(
            apiKeyDoc.creationTime,
            apiKeyDoc.expirationTime,
            apiKeyDoc.invalidated,
            apiKeyDoc.hash,
            apiKeyDoc.name,
            apiKeyDoc.version,
            apiKeyDoc.creator,
            roleDescriptorsHash,
            limitedByRoleDescriptorsHash,
            success,
            apiKey
        );
    }

}
