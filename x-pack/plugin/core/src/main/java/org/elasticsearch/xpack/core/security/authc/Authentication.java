/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.core.security.authc;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.Assertions;
import org.elasticsearch.TransportVersion;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.util.ArrayUtils;
import org.elasticsearch.common.util.Maps;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.core.CheckedFunction;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.core.Strings;
import org.elasticsearch.xcontent.ConstructingObjectParser;
import org.elasticsearch.xcontent.ParseField;
import org.elasticsearch.xcontent.ToXContentObject;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.core.security.authc.RemoteAccessAuthentication.RoleDescriptorsBytes;
import org.elasticsearch.xpack.core.security.authc.esnative.NativeRealmSettings;
import org.elasticsearch.xpack.core.security.authc.file.FileRealmSettings;
import org.elasticsearch.xpack.core.security.authc.service.ServiceAccountSettings;
import org.elasticsearch.xpack.core.security.authc.support.AuthenticationContextSerializer;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.user.AnonymousUser;
import org.elasticsearch.xpack.core.security.user.AsyncSearchUser;
import org.elasticsearch.xpack.core.security.user.SecurityProfileUser;
import org.elasticsearch.xpack.core.security.user.SystemUser;
import org.elasticsearch.xpack.core.security.user.User;
import org.elasticsearch.xpack.core.security.user.XPackSecurityUser;
import org.elasticsearch.xpack.core.security.user.XPackUser;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.elasticsearch.xcontent.ConstructingObjectParser.constructorArg;
import static org.elasticsearch.xcontent.ConstructingObjectParser.optionalConstructorArg;
import static org.elasticsearch.xpack.core.security.authc.Authentication.RealmRef.newAnonymousRealmRef;
import static org.elasticsearch.xpack.core.security.authc.Authentication.RealmRef.newApiKeyRealmRef;
import static org.elasticsearch.xpack.core.security.authc.Authentication.RealmRef.newInternalAttachRealmRef;
import static org.elasticsearch.xpack.core.security.authc.Authentication.RealmRef.newInternalFallbackRealmRef;
import static org.elasticsearch.xpack.core.security.authc.Authentication.RealmRef.newRemoteAccessRealmRef;
import static org.elasticsearch.xpack.core.security.authc.Authentication.RealmRef.newServiceAccountRealmRef;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.ANONYMOUS_REALM_NAME;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.ANONYMOUS_REALM_TYPE;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.API_KEY_REALM_NAME;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.API_KEY_REALM_TYPE;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.ATTACH_REALM_NAME;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.ATTACH_REALM_TYPE;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.FALLBACK_REALM_NAME;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.FALLBACK_REALM_TYPE;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.REMOTE_ACCESS_AUTHENTICATION_KEY;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.REMOTE_ACCESS_REALM_NAME;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.REMOTE_ACCESS_REALM_TYPE;
import static org.elasticsearch.xpack.core.security.authc.AuthenticationField.REMOTE_ACCESS_ROLE_DESCRIPTORS_KEY;
import static org.elasticsearch.xpack.core.security.authc.RealmDomain.REALM_DOMAIN_PARSER;

/**
 * The Authentication class encapsulates identity information created after successful authentication
 * and is the starting point of subsequent authorization.
 *
 * Authentication is serialized and travels across the cluster nodes as the sub-requests are handled,
 * and can also be cached by long-running jobs that continue to act on behalf of the user, beyond
 * the lifetime of the original request.
 *
 * The authentication consists of two {@link Subject}s
 * <ul>
 *     <li>{@link #authenticatingSubject} performs the authentication, i.e. it provides a credential.</li>
 *     <li>{@link #effectiveSubject} The subject that {@link #authenticatingSubject} impersonates ({@link #isRunAs()})</li>
 * </ul>
 * If {@link #isRunAs()} is {@code false}, the two {@link Subject}s will be the same object.
 *
 * Authentication also has a {@link #type} that indicates which mechanism the {@link #authenticatingSubject}
 * uses to perform the authentication.
 *
 * The Authentication's version is its {@link Subject}'s version, i.e. {@code getEffectiveSubject().getTransportVersion()}.
 * It is guaranteed that the versions are identical for the two Subjects. Hence {@code getAuthenticatingSubject().getTransportVersion()}
 * will give out the same result. But using {@code getEffectiveSubject()} is more idiomatic since most callers
 * of this class should just need to know about the {@link #effectiveSubject}. That is, often times, the caller
 * begins with {@code authentication.getEffectiveSubject()} for interrogating an Authentication object.
 */
public final class Authentication implements ToXContentObject {

    private static final Logger logger = LogManager.getLogger(Authentication.class);
    private static final TransportVersion VERSION_AUTHENTICATION_TYPE = TransportVersion.fromId(6_07_00_99);

    public static final TransportVersion VERSION_REMOTE_ACCESS_REALM = TransportVersion.V_8_7_0;
    public static final TransportVersion VERSION_API_KEY_ROLES_AS_BYTES = TransportVersion.V_7_9_0;
    public static final TransportVersion VERSION_REALM_DOMAINS = TransportVersion.V_8_2_0;
    public static final TransportVersion VERSION_METADATA_BEYOND_GENERIC_MAP = TransportVersion.V_8_8_0;
    public static final TransportVersion VERSION_API_KEYS_WITH_REMOTE_INDICES = TransportVersion.V_8_8_0;
    private final AuthenticationType type;
    private final Subject authenticatingSubject;
    private final Subject effectiveSubject;

    private Authentication(Subject subject, AuthenticationType type) {
        this(subject, subject, type);
    }

    private Authentication(Subject effectiveSubject, Subject authenticatingSubject, AuthenticationType type) {
        this.effectiveSubject = Objects.requireNonNull(effectiveSubject, "effective subject cannot be null");
        this.authenticatingSubject = Objects.requireNonNull(authenticatingSubject, "authenticating subject cannot be null");
        this.type = Objects.requireNonNull(type, "authentication type cannot be null");
        if (Assertions.ENABLED) {
            checkConsistency();
        }
    }

    public Authentication(StreamInput in) throws IOException {
        // Read the user(s)
        final User outerUser = AuthenticationSerializationHelper.readUserWithoutTrailingBoolean(in);
        final boolean hasInnerUser;
        if (User.isInternal(outerUser)) {
            hasInnerUser = false;
        } else {
            hasInnerUser = in.readBoolean();
        }
        final User innerUser;
        if (hasInnerUser) {
            innerUser = AuthenticationSerializationHelper.readUserFrom(in);
            assert false == User.isInternal(innerUser) : "internal users cannot participate in run-as";
        } else {
            innerUser = null;
        }

        final RealmRef authenticatedBy = new RealmRef(in);
        final RealmRef lookedUpBy;
        if (in.readBoolean()) {
            lookedUpBy = new RealmRef(in);
        } else {
            lookedUpBy = null;
        }

        // The valid combinations for innerUser and lookedUpBy are:
        // 1. InnerUser == null -> no run-as -> lookedUpBy must be null as well
        // 2. innerUser != null -> lookedUp by can be either null (failed run-as lookup) or non-null (successful lookup)
        // 3. lookedUpBy == null -> innerUser can be either null (no run-as) or non-null (failed run-as lookup)
        // 4. lookedUpBy != null -> successful run-as -> innerUser must be NOT null
        assert innerUser != null || lookedUpBy == null : "Authentication has no inner-user, but looked-up-by is [" + lookedUpBy + "]";

        final TransportVersion version = in.getTransportVersion();
        final Map<String, Object> metadata;
        if (version.onOrAfter(VERSION_AUTHENTICATION_TYPE)) {
            type = AuthenticationType.values()[in.readVInt()];
            metadata = readMetadata(in);
        } else {
            type = AuthenticationType.REALM;
            metadata = Map.of();
        }
        if (innerUser != null) {
            authenticatingSubject = new Subject(innerUser, authenticatedBy, version, metadata);
            // The lookup user for run-as currently doesn't have authentication metadata associated with them because
            // lookupUser only returns the User object. The lookup user for authorization delegation does have
            // authentication metadata, but the realm does not expose this difference between authenticatingUser and
            // delegateUser so effectively this is handled together with the authenticatingSubject not effectiveSubject.
            effectiveSubject = new Subject(outerUser, lookedUpBy, version, Map.of());
        } else {
            authenticatingSubject = effectiveSubject = new Subject(outerUser, authenticatedBy, version, metadata);
        }
        if (Assertions.ENABLED) {
            checkConsistency();
        }
    }

    /**
     * Get the {@link Subject} that performs the actual authentication. This normally means it provides a credentials.
     */
    public Subject getAuthenticatingSubject() {
        return authenticatingSubject;
    }

    /**
     * Get the {@link Subject} that the authentication effectively represents. It may not be the authenticating subject
     * because the authentication subject can run-as another subject.
     */
    public Subject getEffectiveSubject() {
        return effectiveSubject;
    }

    public AuthenticationType getAuthenticationType() {
        return type;
    }

    /**
     * Whether the authentication contains a subject run-as another subject. That is, the authentication subject
     * is different from the effective subject.
     */
    public boolean isRunAs() {
        return authenticatingSubject != effectiveSubject;
    }

    public boolean isFailedRunAs() {
        return isRunAs() && effectiveSubject.getRealm() == null;
    }

    /**
     * Returns a new {@code Authentication}, like this one, but which is compatible with older version nodes.
     * This is commonly employed when the {@code Authentication} is serialized across cluster nodes with mixed versions.
     */
    public Authentication maybeRewriteForOlderVersion(TransportVersion olderVersion) {
        // TODO how can this not be true
        // assert olderVersion.onOrBefore(getVersion());

        // remote access introduced a new synthetic realm and subject type; these cannot be parsed by older versions, so rewriting is not
        // possible
        if (isRemoteAccess() && olderVersion.before(VERSION_REMOTE_ACCESS_REALM)) {
            throw new IllegalArgumentException(
                "versions of Elasticsearch before ["
                    + VERSION_REMOTE_ACCESS_REALM
                    + "] can't handle remote access authentication and attempted to rewrite for ["
                    + olderVersion
                    + "]"
            );
        }

        final Map<String, Object> newMetadata = maybeRewriteMetadata(olderVersion, this);
        final Authentication newAuthentication;
        if (isRunAs()) {
            // The lookup user for run-as currently doesn't have authentication metadata associated with them because
            // lookupUser only returns the User object. The lookup user for authorization delegation does have
            // authentication metadata, but the realm does not expose this difference between authenticatingUser and
            // delegateUser so effectively this is handled together with the authenticatingSubject not effectiveSubject.
            newAuthentication = new Authentication(
                new Subject(
                    effectiveSubject.getUser(),
                    maybeRewriteRealmRef(olderVersion, effectiveSubject.getRealm()),
                    olderVersion,
                    effectiveSubject.getMetadata()
                ),
                new Subject(
                    authenticatingSubject.getUser(),
                    maybeRewriteRealmRef(olderVersion, authenticatingSubject.getRealm()),
                    olderVersion,
                    newMetadata
                ),
                type
            );
        } else {
            newAuthentication = new Authentication(
                new Subject(
                    authenticatingSubject.getUser(),
                    maybeRewriteRealmRef(olderVersion, authenticatingSubject.getRealm()),
                    olderVersion,
                    newMetadata
                ),
                type
            );

        }
        return newAuthentication;
    }

    private static Map<String, Object> maybeRewriteMetadata(TransportVersion olderVersion, Authentication authentication) {
        if (authentication.isAuthenticatedAsApiKey()) {
            return maybeRewriteMetadataForApiKeyRoleDescriptors(olderVersion, authentication);
        } else if (authentication.isRemoteAccess()) {
            return maybeRewriteMetadataForRemoteAccessAuthentication(olderVersion, authentication);
        } else {
            return authentication.getAuthenticatingSubject().getMetadata();
        }
    }

    /**
     * Returns a new {@code Authentication} that reflects a "run as another user" action under the current {@code Authentication}.
     * The security {@code RealmRef#Domain} of the resulting {@code Authentication} is that of the run-as user's realm.
     *
     * @param runAs The user to be impersonated
     * @param lookupRealmRef The realm where the impersonated user is looked up from. It can be null if the user does
     *                       not exist. The null lookup realm is used to indicate the lookup failure which will be rejected
     *                       at authorization time.
     */
    public Authentication runAs(User runAs, @Nullable RealmRef lookupRealmRef) {
        assert supportsRunAs(null);
        assert false == runAs instanceof AnonymousUser;
        assert false == hasSyntheticRealmNameOrType(lookupRealmRef) : "should not use synthetic realm name/type for lookup realms";

        Objects.requireNonNull(runAs);
        return new Authentication(
            new Subject(runAs, lookupRealmRef, getEffectiveSubject().getTransportVersion(), Map.of()),
            authenticatingSubject,
            type
        );
    }

    /** Returns a new {@code Authentication} for tokens created by the current {@code Authentication}, which is used when
     * authenticating using the token credential.
     */
    public Authentication token() {
        assert false == isAuthenticatedInternally();
        assert false == isServiceAccount();
        assert false == isRemoteAccess();
        final Authentication newTokenAuthentication = new Authentication(effectiveSubject, authenticatingSubject, AuthenticationType.TOKEN);
        return newTokenAuthentication;
    }

    /**
      * The final list of roles a user has should include all roles granted to the anonymous user when
      *  1. Anonymous access is enable
      *  2. The user itself is not the anonymous user
      *  3. The authentication is not an API key or service account
      *
      *  Depending on whether the above criteria is satisfied, the method may either return a new
      *  authentication object incorporating anonymous roles or the same authentication object (if anonymous
      *  roles are not applicable)
      *
      *  NOTE this method is an artifact of how anonymous roles are resolved today on each node as opposed to
      *  just on the coordinating node. Whether this behaviour should be changed is an ongoing discussion.
      *  Therefore, using this method in more places other than its current usage requires careful consideration.
      */
    public Authentication maybeAddAnonymousRoles(@Nullable AnonymousUser anonymousUser) {
        final boolean shouldAddAnonymousRoleNames = anonymousUser != null
            && anonymousUser.enabled()
            && false == anonymousUser.equals(getEffectiveSubject().getUser())
            && false == User.isInternal(getEffectiveSubject().getUser())
            && false == isApiKey()
            && false == isRemoteAccess()
            && false == isServiceAccount();

        if (false == shouldAddAnonymousRoleNames) {
            return this;
        }

        // TODO: should we validate enable status and length of role names on instantiation time of anonymousUser?
        if (anonymousUser.roles().length == 0) {
            throw new IllegalStateException("anonymous is only enabled when the anonymous user has roles");
        }
        final String[] allRoleNames = ArrayUtils.concat(getEffectiveSubject().getUser().roles(), anonymousUser.roles());

        if (isRunAs()) {
            final User user = effectiveSubject.getUser();
            return new Authentication(
                new Subject(
                    new User(user.principal(), allRoleNames, user.fullName(), user.email(), user.metadata(), user.enabled()),
                    effectiveSubject.getRealm(),
                    effectiveSubject.getTransportVersion(),
                    effectiveSubject.getMetadata()
                ),
                authenticatingSubject,
                type
            );

        } else {
            final User user = authenticatingSubject.getUser();
            return new Authentication(
                new Subject(
                    new User(user.principal(), allRoleNames, user.fullName(), user.email(), user.metadata(), user.enabled()),
                    authenticatingSubject.getRealm(),
                    authenticatingSubject.getTransportVersion(),
                    authenticatingSubject.getMetadata()
                ),
                type
            );
        }
    }

    // Package private for tests
    /**
     * Returns {@code true} if the effective user belongs to a realm under a domain.
     */
    boolean isAssignedToDomain() {
        return getDomain() != null;
    }

    // Package private for tests
    /**
     * Returns the {@link RealmDomain} that the effective user belongs to.
     * A user belongs to a realm which in turn belongs to a domain.
     *
     * The same username can be authenticated by different realms (e.g. with different credential types),
     * but resources created across realms cannot be accessed unless the realms are also part of the same domain.
     */
    @Nullable
    RealmDomain getDomain() {
        if (isFailedRunAs()) {
            return null;
        }
        return getEffectiveSubject().getRealm().getDomain();
    }

    /**
     * Whether the authenticating user is an API key, including a simple API key or a token created by an API key.
     */
    public boolean isAuthenticatedAsApiKey() {
        return authenticatingSubject.getType() == Subject.Type.API_KEY;
    }

    // TODO: this is not entirely accurate if anonymous user can create a token
    private boolean isAuthenticatedAnonymously() {
        return AuthenticationType.ANONYMOUS.equals(getAuthenticationType());
    }

    private boolean isAuthenticatedInternally() {
        return AuthenticationType.INTERNAL.equals(getAuthenticationType());
    }

    /**
     * Authenticate with a service account and no run-as
     */
    public boolean isServiceAccount() {
        return effectiveSubject.getType() == Subject.Type.SERVICE_ACCOUNT;
    }

    /**
     * Whether the effective user is an API key, this including a simple API key authentication
     * or a token created by the API key.
     */
    public boolean isApiKey() {
        return effectiveSubject.getType() == Subject.Type.API_KEY;
    }

    public boolean isRemoteAccess() {
        return effectiveSubject.getType() == Subject.Type.REMOTE_ACCESS;
    }

    /**
     * Whether the authentication can run-as another user
     */
    public boolean supportsRunAs(@Nullable AnonymousUser anonymousUser) {
        // Chained run-as not allowed
        if (isRunAs()) {
            return false;
        }

        // We may allow service account to run-as in the future, but for now no service account requires it
        if (isServiceAccount()) {
            return false;
        }

        // Real run-as for remote access could happen on the querying cluster side, but not on the fulfilling cluster. Since the
        // authentication instance corresponds to the fulfilling-cluster-side view, run-as is not supported
        if (isRemoteAccess()) {
            return false;
        }

        // There is no reason for internal users to run-as. This check prevents either internal user itself
        // or a token created for it (though no such thing in current code) to run-as.
        if (User.isInternal(getEffectiveSubject().getUser())) {
            return false;
        }

        // Anonymous user or its token cannot run-as
        // There is no perfect way to determine an anonymous user if we take custom realms into consideration
        // 1. A custom realm can return a user object that can pass `equals(anonymousUser)` check
        // (this is the existing check used elsewhere)
        // 2. A custom realm can declare its type and name to be __anonymous
        //
        // This problem is at least partly due to we don't have special serialisation for the AnonymousUser class.
        // As a result, it is serialised just as a normal user. At deserializing time, it is impossible to reliably
        // tell the difference. This is what happens when AnonymousUser creates a token.
        // Also, if anonymous access is disabled or anonymous username, roles are changed after the token is created.
        // Should we still consider the token being created by an anonymous user which is now different from the new
        // anonymous user?
        if (getEffectiveSubject().getUser().equals(anonymousUser)) {
            assert ANONYMOUS_REALM_TYPE.equals(getAuthenticatingSubject().getRealm().getType())
                && ANONYMOUS_REALM_NAME.equals(getAuthenticatingSubject().getRealm().getName());
            return false;
        }

        // Run-as is supported for authentication with realm, api_key or token.
        if (AuthenticationType.REALM == getAuthenticationType()
            || AuthenticationType.API_KEY == getAuthenticationType()
            || AuthenticationType.TOKEN == getAuthenticationType()) {
            return true;
        }

        return false;
    }

    /**
     * Writes the authentication to the context. There must not be an existing authentication in the context and if there is an
     * {@link IllegalStateException} will be thrown
     */
    public void writeToContext(ThreadContext ctx) throws IOException, IllegalArgumentException {
        new AuthenticationContextSerializer().writeToContext(this, ctx);
    }

    public String encode() throws IOException {
        BytesStreamOutput output = new BytesStreamOutput();
        output.setTransportVersion(getEffectiveSubject().getTransportVersion());
        TransportVersion.writeVersion(getEffectiveSubject().getTransportVersion(), output);
        writeTo(output);
        return Base64.getEncoder().encodeToString(BytesReference.toBytes(output.bytes()));
    }

    public void writeTo(StreamOutput out) throws IOException {
        // remote access introduced a new synthetic realm and subject type; these cannot be parsed by older versions, so rewriting we should
        // not send them across the wire to older nodes
        if (isRemoteAccess() && out.getTransportVersion().before(VERSION_REMOTE_ACCESS_REALM)) {
            throw new IllegalArgumentException(
                "versions of Elasticsearch before ["
                    + VERSION_REMOTE_ACCESS_REALM
                    + "] can't handle remote access authentication and attempted to send to ["
                    + out.getTransportVersion()
                    + "]"
            );
        }
        if (isRunAs()) {
            final User outerUser = effectiveSubject.getUser();
            final User innerUser = authenticatingSubject.getUser();
            assert false == User.isInternal(outerUser) && false == User.isInternal(innerUser)
                : "internal users cannot participate in run-as";
            User.writeUser(outerUser, out);
            out.writeBoolean(true);
            User.writeUser(innerUser, out);
            out.writeBoolean(false);
        } else {
            final User user = effectiveSubject.getUser();
            AuthenticationSerializationHelper.writeUserTo(user, out);
        }
        authenticatingSubject.getRealm().writeTo(out);
        final RealmRef lookedUpBy = isRunAs() ? effectiveSubject.getRealm() : null;

        if (lookedUpBy != null) {
            out.writeBoolean(true);
            lookedUpBy.writeTo(out);
        } else {
            out.writeBoolean(false);
        }
        final Map<String, Object> metadata = getAuthenticatingSubject().getMetadata();
        if (out.getTransportVersion().onOrAfter(VERSION_AUTHENTICATION_TYPE)) {
            out.writeVInt(type.ordinal());
            writeMetadata(out, metadata);
        } else {
            assert type == AuthenticationType.REALM && metadata.isEmpty()
                : Strings.format(
                    "authentication with version [%s] must have authentication type %s and empty metadata, but got [%s] and [%s]",
                    out.getTransportVersion(),
                    AuthenticationType.REALM,
                    type,
                    metadata
                );
        }
    }

    /**
     * Checks whether the current authentication, which can be for a user or for an API Key, can access the resources
     * (e.g. search scrolls and async search results) created (owned) by the passed in authentication.
     *
     * The rules are as follows:
     *   * a resource created by an API Key can only be accessed by the exact same key; the creator user, its tokens,
     *   or any of its other keys cannot access it.
     *   * a resource created by a user authenticated by a realm, or any of its tokens, can be accessed by the same
     *   username authenticated by the same realm or by other realms from the same security domain (at the time of the
     *   access), or any of its tokens; realms are considered the same if they have the same type and name (except for
     *   file and native realms, for which only the type is considered, the name is irrelevant), see also
     *      <a href="https://www.elastic.co/guide/en/elasticsearch/reference/master/security-limitations.html">
     *      security limitations</a>
     */
    public boolean canAccessResourcesOf(Authentication resourceCreatorAuthentication) {
        // if we introduce new authentication types in the future, it is likely that we'll need to revisit this method
        assert EnumSet.of(
            Authentication.AuthenticationType.REALM,
            Authentication.AuthenticationType.API_KEY,
            Authentication.AuthenticationType.TOKEN,
            Authentication.AuthenticationType.ANONYMOUS,
            Authentication.AuthenticationType.INTERNAL
        ).containsAll(EnumSet.of(getAuthenticationType(), resourceCreatorAuthentication.getAuthenticationType()))
            : "cross AuthenticationType comparison for canAccessResourcesOf is not applicable for: "
                + EnumSet.of(getAuthenticationType(), resourceCreatorAuthentication.getAuthenticationType());
        final Subject mySubject = getEffectiveSubject();
        final Subject creatorSubject = resourceCreatorAuthentication.getEffectiveSubject();
        return mySubject.canAccessResourcesOf(creatorSubject);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Authentication that = (Authentication) o;
        return type == that.type
            && authenticatingSubject.equals(that.authenticatingSubject)
            && effectiveSubject.equals(that.effectiveSubject);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, authenticatingSubject, effectiveSubject);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        toXContentFragment(builder);
        return builder.endObject();
    }

    /**
     * Generates XContent without the start/end object.
     */
    public void toXContentFragment(XContentBuilder builder) throws IOException {
        final User user = effectiveSubject.getUser();
        builder.field(User.Fields.USERNAME.getPreferredName(), user.principal());
        builder.array(User.Fields.ROLES.getPreferredName(), user.roles());
        builder.field(User.Fields.FULL_NAME.getPreferredName(), user.fullName());
        builder.field(User.Fields.EMAIL.getPreferredName(), user.email());
        if (isServiceAccount()) {
            final String tokenName = (String) getAuthenticatingSubject().getMetadata().get(ServiceAccountSettings.TOKEN_NAME_FIELD);
            assert tokenName != null : "token name cannot be null";
            final String tokenSource = (String) getAuthenticatingSubject().getMetadata().get(ServiceAccountSettings.TOKEN_SOURCE_FIELD);
            assert tokenSource != null : "token source cannot be null";
            builder.field(
                User.Fields.TOKEN.getPreferredName(),
                Map.of("name", tokenName, "type", ServiceAccountSettings.REALM_TYPE + "_" + tokenSource)
            );
        }
        builder.field(User.Fields.METADATA.getPreferredName(), user.metadata());
        builder.field(User.Fields.ENABLED.getPreferredName(), user.enabled());
        builder.startObject(User.Fields.AUTHENTICATION_REALM.getPreferredName());
        builder.field(User.Fields.REALM_NAME.getPreferredName(), getAuthenticatingSubject().getRealm().getName());
        builder.field(User.Fields.REALM_TYPE.getPreferredName(), getAuthenticatingSubject().getRealm().getType());
        // domain name is generally ambiguous, because it can change during the lifetime of the authentication,
        // but it is good enough for display purposes (including auditing)
        if (getAuthenticatingSubject().getRealm().getDomain() != null) {
            builder.field(User.Fields.REALM_DOMAIN.getPreferredName(), getAuthenticatingSubject().getRealm().getDomain().name());
        }
        builder.endObject();
        builder.startObject(User.Fields.LOOKUP_REALM.getPreferredName());
        final RealmRef lookedUpBy = isRunAs() ? getEffectiveSubject().getRealm() : null;
        if (lookedUpBy != null) {
            builder.field(User.Fields.REALM_NAME.getPreferredName(), lookedUpBy.getName());
            builder.field(User.Fields.REALM_TYPE.getPreferredName(), lookedUpBy.getType());
            if (lookedUpBy.getDomain() != null) {
                builder.field(User.Fields.REALM_DOMAIN.getPreferredName(), lookedUpBy.getDomain().name());
            }
        } else {
            builder.field(User.Fields.REALM_NAME.getPreferredName(), getAuthenticatingSubject().getRealm().getName());
            builder.field(User.Fields.REALM_TYPE.getPreferredName(), getAuthenticatingSubject().getRealm().getType());
            if (getAuthenticatingSubject().getRealm().getDomain() != null) {
                builder.field(User.Fields.REALM_DOMAIN.getPreferredName(), getAuthenticatingSubject().getRealm().getDomain().name());
            }
        }
        builder.endObject();
        builder.field(User.Fields.AUTHENTICATION_TYPE.getPreferredName(), getAuthenticationType().name().toLowerCase(Locale.ROOT));
        if (isApiKey() || isRemoteAccess()) {
            final String apiKeyId = (String) getAuthenticatingSubject().getMetadata().get(AuthenticationField.API_KEY_ID_KEY);
            final String apiKeyName = (String) getAuthenticatingSubject().getMetadata().get(AuthenticationField.API_KEY_NAME_KEY);
            if (apiKeyName == null) {
                builder.field("api_key", Map.of("id", apiKeyId));
            } else {
                builder.field("api_key", Map.of("id", apiKeyId, "name", apiKeyName));
            }
        }
    }

    private static final Map<String, CheckedFunction<StreamInput, Object, IOException>> METADATA_VALUE_READER = Map.of(
        REMOTE_ACCESS_AUTHENTICATION_KEY,
        Authentication::new,
        REMOTE_ACCESS_ROLE_DESCRIPTORS_KEY,
        in -> in.readList(RoleDescriptorsBytes::new)
    );

    private static Map<String, Object> readMetadata(StreamInput in) throws IOException {
        if (in.getTransportVersion().onOrAfter(VERSION_METADATA_BEYOND_GENERIC_MAP)) {
            final int size = in.readVInt();
            final Map<String, Object> metadata = Maps.newHashMapWithExpectedSize(size);
            for (int i = 0; i < size; i++) {
                final String key = in.readString();
                final Object value = METADATA_VALUE_READER.getOrDefault(key, StreamInput::readGenericValue).apply(in);
                metadata.put(key, value);
            }
            return metadata;
        } else {
            return in.readMap();
        }
    }

    private static final Map<String, Writeable.Writer<?>> METADATA_VALUE_WRITER = Map.of(
        REMOTE_ACCESS_AUTHENTICATION_KEY,
        (out, v) -> ((Authentication) v).writeTo(out),
        REMOTE_ACCESS_ROLE_DESCRIPTORS_KEY,
        (out, v) -> {
            @SuppressWarnings("unchecked")
            final List<RoleDescriptorsBytes> roleDescriptorsBytesList = (List<RoleDescriptorsBytes>) v;
            out.writeCollection(roleDescriptorsBytesList, (o, rdb) -> rdb.writeTo(o));
        }
    );

    private static void writeMetadata(StreamOutput out, Map<String, Object> metadata) throws IOException {
        if (out.getTransportVersion().onOrAfter(VERSION_METADATA_BEYOND_GENERIC_MAP)) {
            out.writeVInt(metadata.size());
            for (Map.Entry<String, Object> entry : metadata.entrySet()) {
                out.writeString(entry.getKey());
                @SuppressWarnings("unchecked")
                final var valueWriter = (Writeable.Writer<Object>) METADATA_VALUE_WRITER.getOrDefault(
                    entry.getKey(),
                    StreamOutput::writeGenericValue
                );
                valueWriter.write(out, entry.getValue());
            }
        } else {
            out.writeGenericMap(metadata);
        }
    }

    /**
     * An Authentication object has internal constraint between its fields, e.g. if it is internal authentication,
     * it must have an internal user. These logics are upheld when authentication is built as a result of successful
     * authentication. Hence, this method mostly runs in test (where assertion is enabled).
     * However, for RCS remote access, FC receives an authentication object as part of the request. There is
     * no guarantee that this authentication object also maintains the internal logics. Therefore, this method
     * is called explicitly in production when handling remote access requests.
     */
    public void checkConsistency() {
        // isRunAs logic consistency
        if (isRunAs()) {
            assert authenticatingSubject != effectiveSubject : "isRunAs logic does not hold";
        } else {
            assert authenticatingSubject == effectiveSubject : "isRunAs logic does not hold";
        }

        // check consistency for each authentication type
        if (isAuthenticatedAnonymously()) {
            checkConsistencyForAnonymousAuthenticationType();
        } else if (isAuthenticatedInternally()) {
            checkConsistencyForInternalAuthenticationType();
        } else if (type == AuthenticationType.API_KEY) {
            checkConsistencyForApiKeyAuthenticationType();
        } else if (type == AuthenticationType.REALM) {
            checkConsistencyForRealmAuthenticationType();
        } else if (type == AuthenticationType.TOKEN) {
            checkConsistencyForTokenAuthenticationType();
        } else {
            assert false : "unknown authentication type " + type;
        }
    }

    private void checkConsistencyForAnonymousAuthenticationType() {
        final RealmRef authenticatingRealm = authenticatingSubject.getRealm();
        if (false == authenticatingRealm.isAnonymousRealm()) {
            throw new IllegalArgumentException(
                Strings.format("Anonymous authentication cannot have realm type [%s]", authenticatingRealm.type)
            );
        }
        if (authenticatingRealm.getDomain() != null) {
            throw new IllegalArgumentException("Anonymous authentication cannot have domain");
        }
        checkNotInternalUser(authenticatingSubject, "Anonymous authentication cannot have internal user [%s]");
        if (isRunAs()) {
            throw new IllegalArgumentException("Anonymous authentication cannot have run-as");
        }
    }

    private void checkConsistencyForInternalAuthenticationType() {
        final RealmRef authenticatingRealm = authenticatingSubject.getRealm();
        if (false == authenticatingRealm.isFallbackRealm() && false == authenticatingRealm.isAttachRealm()) {
            throw new IllegalArgumentException(
                Strings.format("Internal authentication cannot have realm type [%s]", authenticatingRealm.type)
            );
        }
        if (authenticatingRealm.getDomain() != null) {
            throw new IllegalArgumentException("Internal authentication cannot have domain");
        }
        if (false == User.isInternal(authenticatingSubject.getUser())) {
            throw new IllegalArgumentException("Internal authentication must have internal user");
        }
        if (isRunAs()) {
            throw new IllegalArgumentException("Internal authentication cannot have run-as");
        }
    }

    private void checkConsistencyForApiKeyAuthenticationType() {
        final RealmRef authenticatingRealm = authenticatingSubject.getRealm();
        if (false == authenticatingRealm.isApiKeyRealm() && false == authenticatingRealm.isRemoteAccessRealm()) {
            throw new IllegalArgumentException(
                Strings.format("API key authentication cannot have realm type [%s]", authenticatingRealm.type)
            );
        }
        if (authenticatingRealm.getDomain() != null) {
            throw new IllegalArgumentException("API key authentication cannot have domain");
        }
        checkNotInternalUser(authenticatingSubject, "API key authentication cannot have internal user [%s]");
        if (authenticatingSubject.getUser().roles().length != 0) {
            throw new IllegalArgumentException("API key authentication user must have no role");
        }
        if (authenticatingSubject.getMetadata().get(AuthenticationField.API_KEY_ID_KEY) == null) {
            throw new IllegalArgumentException("API key authentication requires metadata to contain a non-null API key ID");
        }
        if (Subject.Type.REMOTE_ACCESS == authenticatingSubject.getType()) {
            if (authenticatingSubject.getMetadata().get(REMOTE_ACCESS_AUTHENTICATION_KEY) == null) {
                throw new IllegalArgumentException(
                    "Remote access authentication requires metadata to contain a non-null serialized remote access authentication"
                );
            }
            if (authenticatingSubject.getMetadata().get(REMOTE_ACCESS_ROLE_DESCRIPTORS_KEY) == null) {
                throw new IllegalArgumentException(
                    "Remote access authentication requires metadata to contain a non-null serialized remote access role descriptors"
                );
            }
            if (isRunAs()) {
                throw new IllegalArgumentException("Remote access authentication cannot run-as other user");
            }
        } else {
            if (isRunAs()) {
                checkRunAsConsistency(effectiveSubject, authenticatingSubject);
            }
        }
    }

    private void checkConsistencyForRealmAuthenticationType() {
        if (Subject.Type.USER != authenticatingSubject.getType()) {
            throw new IllegalArgumentException("Realm authentication must have subject type of user");
        }
        if (isRunAs()) {
            checkRunAsConsistency(effectiveSubject, authenticatingSubject);
        }
    }

    private void checkConsistencyForTokenAuthenticationType() {
        final RealmRef authenticatingRealm = authenticatingSubject.getRealm();
        assert false == authenticatingRealm.isAttachRealm()
            && false == authenticatingRealm.isFallbackRealm()
            && false == authenticatingRealm.isRemoteAccessRealm()
            : "Token authentication cannot have authenticating realm " + authenticatingRealm;

        checkNotInternalUser(authenticatingSubject, "Token authentication cannot have internal user [%s]");
        if (Subject.Type.SERVICE_ACCOUNT == authenticatingSubject.getType()) {
            if (authenticatingRealm.getDomain() != null) {
                throw new IllegalArgumentException("Service account authentication cannot have domain");
            }
            if (authenticatingSubject.getUser().roles().length != 0) {
                throw new IllegalArgumentException("Service account authentication user must have no role");
            }
            if (isRunAs()) {
                throw new IllegalArgumentException("Service account authentication cannot run-as other user");
            }
        } else {
            if (isRunAs()) {
                checkRunAsConsistency(effectiveSubject, authenticatingSubject);
            }
        }
    }

    private static void checkRunAsConsistency(Subject effectiveSubject, Subject authenticatingSubject) {
        if (false == effectiveSubject.getTransportVersion().equals(authenticatingSubject.getTransportVersion())) {
            throw new IllegalArgumentException(
                Strings.format(
                    "inconsistent versions between effective subject [%s] and authenticating subject [%s]",
                    effectiveSubject.getTransportVersion(),
                    authenticatingSubject.getTransportVersion()
                )
            );
        }
        if (Subject.Type.USER != effectiveSubject.getType()) {
            throw new IllegalArgumentException(Strings.format("Run-as subject type cannot be [%s]", effectiveSubject.getType()));
        }
        if (false == effectiveSubject.getMetadata().isEmpty()) {
            throw new IllegalArgumentException("Run-as subject must have empty metadata");
        }
        // assert here because it does not hold for custom realm
        assert false == hasSyntheticRealmNameOrType(effectiveSubject.getRealm()) : "run-as subject cannot be from a synthetic realm";
    }

    private static void checkNotInternalUser(Subject subject, String templateMessage) {
        if (User.isInternal(subject.getUser())) {
            throw new IllegalArgumentException(Strings.format(templateMessage, subject.getUser().principal()));
        }
    }

    private static boolean hasSyntheticRealmNameOrType(@Nullable RealmRef realmRef) {
        if (realmRef == null) {
            return false;
        }
        if (List.of(
            API_KEY_REALM_NAME,
            ServiceAccountSettings.REALM_NAME,
            ANONYMOUS_REALM_NAME,
            FALLBACK_REALM_NAME,
            ATTACH_REALM_NAME,
            REMOTE_ACCESS_REALM_NAME
        ).contains(realmRef.getName())) {
            return true;
        }
        if (List.of(
            API_KEY_REALM_TYPE,
            ServiceAccountSettings.REALM_TYPE,
            ANONYMOUS_REALM_TYPE,
            FALLBACK_REALM_TYPE,
            ATTACH_REALM_TYPE,
            REMOTE_ACCESS_REALM_TYPE
        ).contains(realmRef.getType())) {
            return true;
        }
        return false;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder("Authentication[effectiveSubject=").append(effectiveSubject);
        if (isRunAs()) {
            builder.append(",authenticatingSubject=").append(authenticatingSubject);
        }
        builder.append(",type=").append(type);
        builder.append("]");
        return builder.toString();
    }

    public static class RealmRef implements Writeable, ToXContentObject {

        private final String nodeName;
        private final String name;
        private final String type;
        private final @Nullable RealmDomain domain;

        public RealmRef(String name, String type, String nodeName) {
            this(name, type, nodeName, null);
        }

        public RealmRef(String name, String type, String nodeName, @Nullable RealmDomain domain) {
            this.nodeName = Objects.requireNonNull(nodeName, "node name cannot be null");
            this.name = Objects.requireNonNull(name, "realm name cannot be null");
            this.type = Objects.requireNonNull(type, "realm type cannot be null");
            this.domain = domain;
        }

        public RealmRef(StreamInput in) throws IOException {
            this.nodeName = in.readString();
            this.name = in.readString();
            this.type = in.readString();
            if (in.getTransportVersion().onOrAfter(VERSION_REALM_DOMAINS)) {
                this.domain = in.readOptionalWriteable(RealmDomain::readFrom);
            } else {
                this.domain = null;
            }
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeString(nodeName);
            out.writeString(name);
            out.writeString(type);
            if (out.getTransportVersion().onOrAfter(VERSION_REALM_DOMAINS)) {
                out.writeOptionalWriteable(domain);
            }
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            {
                builder.field("name", name);
                builder.field("type", type);
                builder.field("node_name", nodeName);
                if (domain != null) {
                    builder.field("domain", domain);
                }
            }
            builder.endObject();
            return builder;
        }

        public String getNodeName() {
            return nodeName;
        }

        public String getName() {
            return name;
        }

        public String getType() {
            return type;
        }

        /**
         * Returns the domain assignment for the realm, if one assigned, or {@code null} otherwise, as per the
         * {@code RealmSettings#DOMAIN_TO_REALM_ASSOC_SETTING} setting.
         */
        public @Nullable RealmDomain getDomain() {
            return domain;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            RealmRef realmRef = (RealmRef) o;

            if (nodeName.equals(realmRef.nodeName) == false) return false;
            if (type.equals(realmRef.type) == false) return false;
            return Objects.equals(domain, realmRef.domain);
        }

        @Override
        public int hashCode() {
            int result = nodeName.hashCode();
            result = 31 * result + name.hashCode();
            result = 31 * result + type.hashCode();
            if (domain != null) {
                result = 31 * result + domain.hashCode();
            }
            return result;
        }

        @Override
        public String toString() {
            if (domain != null) {
                return "{Realm[" + type + "." + name + "] under Domain[" + domain.name() + "] on Node[" + nodeName + "]}";
            } else {
                return "{Realm[" + type + "." + name + "] on Node[" + nodeName + "]}";
            }
        }

        private boolean isFallbackRealm() {
            return FALLBACK_REALM_NAME.equals(name) && FALLBACK_REALM_TYPE.equals(type);
        }

        private boolean isAttachRealm() {
            return ATTACH_REALM_NAME.equals(name) && ATTACH_REALM_TYPE.equals(type);
        }

        private boolean isAnonymousRealm() {
            return ANONYMOUS_REALM_NAME.equals(name) && ANONYMOUS_REALM_TYPE.equals(type);
        }

        private boolean isApiKeyRealm() {
            return API_KEY_REALM_NAME.equals(name) && API_KEY_REALM_TYPE.equals(type);
        }

        private boolean isServiceAccountRealm() {
            return ServiceAccountSettings.REALM_NAME.equals(name) && ServiceAccountSettings.REALM_TYPE.equals(type);
        }

        private boolean isRemoteAccessRealm() {
            return REMOTE_ACCESS_REALM_NAME.equals(name) && REMOTE_ACCESS_REALM_TYPE.equals(type);
        }

        static RealmRef newInternalAttachRealmRef(String nodeName) {
            // the "attach" internal realm is not part of any realm domain
            return new Authentication.RealmRef(ATTACH_REALM_NAME, ATTACH_REALM_TYPE, nodeName, null);
        }

        static RealmRef newInternalFallbackRealmRef(String nodeName) {
            // the "fallback" internal realm is not part of any realm domain
            RealmRef realmRef = new RealmRef(FALLBACK_REALM_NAME, FALLBACK_REALM_TYPE, nodeName, null);
            return realmRef;
        }

        public static RealmRef newAnonymousRealmRef(String nodeName) {
            // the "anonymous" internal realm is not part of any realm domain
            return new Authentication.RealmRef(ANONYMOUS_REALM_NAME, ANONYMOUS_REALM_TYPE, nodeName, null);
        }

        static RealmRef newServiceAccountRealmRef(String nodeName) {
            // no domain for service account tokens
            return new Authentication.RealmRef(ServiceAccountSettings.REALM_NAME, ServiceAccountSettings.REALM_TYPE, nodeName, null);
        }

        static RealmRef newApiKeyRealmRef(String nodeName) {
            // no domain for API Key tokens
            return new RealmRef(API_KEY_REALM_NAME, API_KEY_REALM_TYPE, nodeName, null);
        }

        static RealmRef newRemoteAccessRealmRef(String nodeName) {
            // no domain for remote access authentication
            return new RealmRef(REMOTE_ACCESS_REALM_NAME, REMOTE_ACCESS_REALM_TYPE, nodeName, null);
        }
    }

    public static boolean isFileOrNativeRealm(String realmType) {
        return FileRealmSettings.TYPE.equals(realmType) || NativeRealmSettings.TYPE.equals(realmType);
    }

    public static ConstructingObjectParser<RealmRef, Void> REALM_REF_PARSER = new ConstructingObjectParser<>(
        "realm_ref",
        false,
        (args, v) -> new RealmRef((String) args[0], (String) args[1], (String) args[2], (RealmDomain) args[3])
    );

    static {
        REALM_REF_PARSER.declareString(constructorArg(), new ParseField("name"));
        REALM_REF_PARSER.declareString(constructorArg(), new ParseField("type"));
        REALM_REF_PARSER.declareString(constructorArg(), new ParseField("node_name"));
        REALM_REF_PARSER.declareObject(optionalConstructorArg(), (p, c) -> REALM_DOMAIN_PARSER.parse(p, c), new ParseField("domain"));
    }

    // TODO is a newer version than the node's a valid value?
    public static Authentication newInternalAuthentication(User internalUser, TransportVersion version, String nodeName) {
        // TODO create a system user class, so that the type system guarantees that this is only invoked for internal users
        assert User.isInternal(internalUser);
        final Authentication.RealmRef authenticatedBy = newInternalAttachRealmRef(nodeName);
        Authentication authentication = new Authentication(
            new Subject(internalUser, authenticatedBy, version, Map.of()),
            AuthenticationType.INTERNAL
        );
        return authentication;
    }

    public static Authentication newInternalFallbackAuthentication(User fallbackUser, String nodeName) {
        // TODO assert SystemUser.is(fallbackUser);
        final Authentication.RealmRef authenticatedBy = newInternalFallbackRealmRef(nodeName);
        Authentication authentication = new Authentication(
            new Subject(fallbackUser, authenticatedBy, TransportVersion.CURRENT, Map.of()),
            Authentication.AuthenticationType.INTERNAL
        );
        return authentication;
    }

    public static Authentication newAnonymousAuthentication(AnonymousUser anonymousUser, String nodeName) {
        final Authentication.RealmRef authenticatedBy = newAnonymousRealmRef(nodeName);
        Authentication authentication = new Authentication(
            new Subject(anonymousUser, authenticatedBy, TransportVersion.CURRENT, Map.of()),
            Authentication.AuthenticationType.ANONYMOUS
        );
        return authentication;
    }

    public static Authentication newServiceAccountAuthentication(User serviceAccountUser, String nodeName, Map<String, Object> metadata) {
        // TODO make the service account user a separate class/interface
        final Authentication.RealmRef authenticatedBy = newServiceAccountRealmRef(nodeName);
        Authentication authentication = new Authentication(
            new Subject(serviceAccountUser, authenticatedBy, TransportVersion.CURRENT, metadata),
            AuthenticationType.TOKEN
        );
        return authentication;
    }

    public static Authentication newRealmAuthentication(User user, RealmRef realmRef) {
        // TODO make the type system ensure that this is not a run-as user
        Authentication authentication = new Authentication(
            new Subject(user, realmRef, TransportVersion.CURRENT, Map.of()),
            AuthenticationType.REALM
        );
        assert false == authentication.isServiceAccount();
        assert false == authentication.isApiKey();
        assert false == authentication.isRemoteAccess();
        assert false == authentication.isAuthenticatedInternally();
        assert false == authentication.isAuthenticatedAnonymously();
        return authentication;
    }

    public static Authentication newApiKeyAuthentication(AuthenticationResult<User> authResult, String nodeName) {
        assert authResult.isAuthenticated() : "API Key authn result must be successful";
        final User apiKeyUser = authResult.getValue();
        assert apiKeyUser.roles().length == 0 : "The user associated to an API key authentication must have no role";
        final Authentication.RealmRef authenticatedBy = newApiKeyRealmRef(nodeName);
        Authentication authentication = new Authentication(
            new Subject(apiKeyUser, authenticatedBy, TransportVersion.CURRENT, authResult.getMetadata()),
            AuthenticationType.API_KEY
        );
        return authentication;
    }

    public Authentication toRemoteAccess(RemoteAccessAuthentication remoteAccessAuthentication) {
        assert isApiKey() : "can only convert API key authentication to remote access";
        assert false == isRunAs() : "remote access does not support authentication with run-as";
        assert getEffectiveSubject().getUser().roles().length == 0
            : "the user associated with a remote access authentication must have no role";
        final Map<String, Object> metadata = new HashMap<>(getAuthenticatingSubject().getMetadata());
        final Authentication.RealmRef authenticatedBy = newRemoteAccessRealmRef(getAuthenticatingSubject().getRealm().getNodeName());
        final Authentication authentication = new Authentication(
            new Subject(
                getEffectiveSubject().getUser(),
                authenticatedBy,
                TransportVersion.CURRENT,
                remoteAccessAuthentication.copyWithRemoteAccessEntries(metadata)
            ),
            getAuthenticationType()
        );
        return authentication;
    }

    // pkg-private for testing
    static RealmRef maybeRewriteRealmRef(TransportVersion streamVersion, RealmRef realmRef) {
        if (realmRef != null && realmRef.getDomain() != null && streamVersion.before(VERSION_REALM_DOMAINS)) {
            logger.info("Rewriting realm [" + realmRef + "] without domain");
            // security domain erasure
            return new RealmRef(realmRef.getName(), realmRef.getType(), realmRef.getNodeName(), null);
        }
        return realmRef;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> maybeRewriteMetadataForApiKeyRoleDescriptors(
        TransportVersion streamVersion,
        Authentication authentication
    ) {
        Map<String, Object> metadata = authentication.getAuthenticatingSubject().getMetadata();
        // If authentication user is an API key or a token created by an API key,
        // regardless whether it has run-as, the metadata must contain API key role descriptors
        if (authentication.isAuthenticatedAsApiKey()) {
            assert metadata.containsKey(AuthenticationField.API_KEY_ROLE_DESCRIPTORS_KEY)
                : "metadata must contain role descriptor for API key authentication";
            assert metadata.containsKey(AuthenticationField.API_KEY_LIMITED_ROLE_DESCRIPTORS_KEY)
                : "metadata must contain limited role descriptor for API key authentication";
            if (authentication.getEffectiveSubject().getTransportVersion().onOrAfter(VERSION_API_KEYS_WITH_REMOTE_INDICES)
                && streamVersion.before(VERSION_API_KEYS_WITH_REMOTE_INDICES)) {
                metadata = new HashMap<>(metadata);
                metadata.put(
                    AuthenticationField.API_KEY_ROLE_DESCRIPTORS_KEY,
                    maybeRemoveRemoteIndicesFromRoleDescriptors(
                        (BytesReference) metadata.get(AuthenticationField.API_KEY_ROLE_DESCRIPTORS_KEY)
                    )
                );
                metadata.put(
                    AuthenticationField.API_KEY_LIMITED_ROLE_DESCRIPTORS_KEY,
                    maybeRemoveRemoteIndicesFromRoleDescriptors(
                        (BytesReference) metadata.get(AuthenticationField.API_KEY_LIMITED_ROLE_DESCRIPTORS_KEY)
                    )
                );
            }
            if (authentication.getEffectiveSubject().getTransportVersion().onOrAfter(VERSION_API_KEY_ROLES_AS_BYTES)
                && streamVersion.before(VERSION_API_KEY_ROLES_AS_BYTES)) {
                metadata = new HashMap<>(metadata);
                metadata.put(
                    AuthenticationField.API_KEY_ROLE_DESCRIPTORS_KEY,
                    convertRoleDescriptorsBytesToMap((BytesReference) metadata.get(AuthenticationField.API_KEY_ROLE_DESCRIPTORS_KEY))
                );
                metadata.put(
                    AuthenticationField.API_KEY_LIMITED_ROLE_DESCRIPTORS_KEY,
                    convertRoleDescriptorsBytesToMap(
                        (BytesReference) metadata.get(AuthenticationField.API_KEY_LIMITED_ROLE_DESCRIPTORS_KEY)
                    )
                );
            } else if (authentication.getEffectiveSubject().getTransportVersion().before(VERSION_API_KEY_ROLES_AS_BYTES)
                && streamVersion.onOrAfter(VERSION_API_KEY_ROLES_AS_BYTES)) {
                    metadata = new HashMap<>(metadata);
                    metadata.put(
                        AuthenticationField.API_KEY_ROLE_DESCRIPTORS_KEY,
                        convertRoleDescriptorsMapToBytes(
                            (Map<String, Object>) metadata.get(AuthenticationField.API_KEY_ROLE_DESCRIPTORS_KEY)
                        )
                    );
                    metadata.put(
                        AuthenticationField.API_KEY_LIMITED_ROLE_DESCRIPTORS_KEY,
                        convertRoleDescriptorsMapToBytes(
                            (Map<String, Object>) metadata.get(AuthenticationField.API_KEY_LIMITED_ROLE_DESCRIPTORS_KEY)
                        )
                    );
                }
        }
        return metadata;
    }

    // pkg-private for testing
    static Map<String, Object> maybeRewriteMetadataForRemoteAccessAuthentication(
        final TransportVersion olderVersion,
        final Authentication authentication
    ) {
        assert authentication.isRemoteAccess() : "authentication must be remote access";
        final Map<String, Object> metadata = authentication.getAuthenticatingSubject().getMetadata();
        assert metadata.containsKey(REMOTE_ACCESS_AUTHENTICATION_KEY)
            : "metadata must contain authentication object for remote access authentication";
        final Authentication authenticationFromMetadata = (Authentication) metadata.get(REMOTE_ACCESS_AUTHENTICATION_KEY);
        if (authenticationFromMetadata.getEffectiveSubject().getTransportVersion().after(olderVersion)) {
            final Map<String, Object> rewrittenMetadata = new HashMap<>(metadata);
            rewrittenMetadata.put(REMOTE_ACCESS_AUTHENTICATION_KEY, authenticationFromMetadata.maybeRewriteForOlderVersion(olderVersion));
            return rewrittenMetadata;
        } else {
            return metadata;
        }
    }

    private static Map<String, Object> convertRoleDescriptorsBytesToMap(BytesReference roleDescriptorsBytes) {
        return XContentHelper.convertToMap(roleDescriptorsBytes, false, XContentType.JSON).v2();
    }

    private static BytesReference convertRoleDescriptorsMapToBytes(Map<String, Object> roleDescriptorsMap) {
        try (XContentBuilder builder = XContentBuilder.builder(XContentType.JSON.xContent())) {
            builder.map(roleDescriptorsMap);
            return BytesReference.bytes(builder);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static BytesReference maybeRemoveRemoteIndicesFromRoleDescriptors(BytesReference roleDescriptorsBytes) {
        if (roleDescriptorsBytes == null || roleDescriptorsBytes.length() == 0) {
            return roleDescriptorsBytes;
        }

        final Map<String, Object> roleDescriptorsMap = convertRoleDescriptorsBytesToMap(roleDescriptorsBytes);
        final AtomicBoolean removedAtLeastOne = new AtomicBoolean(false);
        roleDescriptorsMap.entrySet().stream().forEach(entry -> {
            if (entry.getValue() instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> roleDescriptor = (Map<String, Object>) entry.getValue();
                boolean removed = roleDescriptor.remove(RoleDescriptor.Fields.REMOTE_INDICES.getPreferredName()) != null;
                if (removed) {
                    removedAtLeastOne.set(true);
                }
            }
        });

        if (removedAtLeastOne.get()) {
            return convertRoleDescriptorsMapToBytes(roleDescriptorsMap);
        } else {
            // No need to serialize if we did not remove anything.
            return roleDescriptorsBytes;
        }
    }

    static boolean equivalentRealms(String name1, String type1, String name2, String type2) {
        if (false == type1.equals(type2)) {
            return false;
        }
        if (isFileOrNativeRealm(type1)) {
            // file and native realms can be renamed, but they always point to the same set of users
            return true;
        } else {
            // if other realms are renamed, it is an indication that they point to a different user set
            return name1.equals(name2);
        }
    }

    // TODO: Rename to AuthenticationMethod
    public enum AuthenticationType {
        REALM,
        API_KEY,
        TOKEN,
        ANONYMOUS,
        INTERNAL
    }

    public static class AuthenticationSerializationHelper {

        private AuthenticationSerializationHelper() {}

        /**
         * Read the User object as well as the trailing boolean flag if the user is *not* an internal user.
         * The trailing boolean, if exits, must be false (indicating no following inner-user).
         */
        public static User readUserFrom(StreamInput input) throws IOException {
            final User user = readUserWithoutTrailingBoolean(input);
            if (false == User.isInternal(user)) {
                boolean hasInnerUser = input.readBoolean();
                assert false == hasInnerUser : "inner user is not allowed";
                if (hasInnerUser) {
                    throw new IllegalStateException("inner user is not allowed");
                }
            }
            return user;
        }

        public static void writeUserTo(User user, StreamOutput output) throws IOException {
            if (User.isInternal(user)) {
                writeInternalUser(user, output);
            } else {
                User.writeUser(user, output);
                output.writeBoolean(false); // simple user, no inner user possible
            }
        }

        private static User readUserWithoutTrailingBoolean(StreamInput input) throws IOException {
            final boolean isInternalUser = input.readBoolean();
            final String username = input.readString();
            if (isInternalUser) {
                if (SystemUser.NAME.equals(username)) {
                    return SystemUser.INSTANCE;
                } else if (XPackUser.NAME.equals(username)) {
                    return XPackUser.INSTANCE;
                } else if (XPackSecurityUser.NAME.equals(username)) {
                    return XPackSecurityUser.INSTANCE;
                } else if (SecurityProfileUser.NAME.equals(username)) {
                    return SecurityProfileUser.INSTANCE;
                } else if (AsyncSearchUser.NAME.equals(username)) {
                    return AsyncSearchUser.INSTANCE;
                }
                throw new IllegalStateException("username [" + username + "] does not match any internal user");
            }
            String[] roles = input.readStringArray();
            Map<String, Object> metadata = input.readMap();
            String fullName = input.readOptionalString();
            String email = input.readOptionalString();
            boolean enabled = input.readBoolean();
            return new User(username, roles, fullName, email, metadata, enabled);
        }

        private static void writeInternalUser(User user, StreamOutput output) throws IOException {
            assert User.isInternal(user);
            output.writeBoolean(true);
            if (SystemUser.is(user)) {
                output.writeString(SystemUser.NAME);
            } else if (XPackUser.is(user)) {
                output.writeString(XPackUser.NAME);
            } else if (XPackSecurityUser.is(user)) {
                output.writeString(XPackSecurityUser.NAME);
            } else if (SecurityProfileUser.is(user)) {
                output.writeString(SecurityProfileUser.NAME);
            } else if (AsyncSearchUser.is(user)) {
                output.writeString(AsyncSearchUser.NAME);
            } else {
                assert false;
                throw new IllegalStateException("user [" + user + "] is not internal");
            }
        }
    }
}
