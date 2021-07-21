/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.core.security.authz.permission;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.util.automaton.Automaton;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.common.util.set.Sets;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.accesscontrol.IndicesAccessControl;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilegeResolver;
import org.elasticsearch.xpack.core.security.authz.privilege.ConfigurableClusterPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.IndexPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.Privilege;
import org.elasticsearch.xpack.core.security.authz.store.ReservedRolesStore;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.SortedMap;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;

public class Role {

    public static final Role EMPTY = Role.builder("__empty").build();
    private static final Logger logger = LogManager.getLogger(Role.class);
    private static final String ANY_ACTION_MARKER = "*";

    private final String[] names;
    private final ClusterPermission cluster;
    private final IndicesPermission indices;
    private final ApplicationPermission application;
    private final RunAsPermission runAs;
    // Weak keys so the JVM is free to claim memories used by the potentially large values
    // WeakHashMap does not have concurrency control but we don't really need it for this usage
    private final WeakHashMap<AuthorizedIndicesKey, AuthorizedIndicesValue> authorizedIndicesCache = new WeakHashMap<>();
    private final AtomicLong currentMetadataVersion = new AtomicLong(-1L);

    Role(String[] names, ClusterPermission cluster, IndicesPermission indices, ApplicationPermission application, RunAsPermission runAs) {
        this.names = names;
        this.cluster = Objects.requireNonNull(cluster);
        this.indices = Objects.requireNonNull(indices);
        this.application = Objects.requireNonNull(application);
        this.runAs = Objects.requireNonNull(runAs);
    }

    public String[] names() {
        return names;
    }

    public ClusterPermission cluster() {
        return cluster;
    }

    public IndicesPermission indices() {
        return indices;
    }

    public ApplicationPermission application() {
        return application;
    }

    public RunAsPermission runAs() {
        return runAs;
    }

    public static Builder builder(String... names) {
        return new Builder(names);
    }

    public static Builder builder(RoleDescriptor rd, FieldPermissionsCache fieldPermissionsCache) {
        return new Builder(rd, fieldPermissionsCache);
    }

    /**
     * @return A predicate that will match all the indices that this role
     * has the privilege for executing the given action on.
     */
    public Predicate<IndexAbstraction> allowedIndicesMatcher(String action) {
        return indices.allowedIndicesMatcher(action);
    }

    public Automaton allowedActionsMatcher(String index) {
        return indices.allowedActionsMatcher(index);
    }

    public boolean checkRunAs(String runAsName) {
        return runAs.check(runAsName);
    }

    /**
     * Check if indices permissions allow for the given action
     *
     * @param action indices action
     * @return {@code true} if action is allowed else returns {@code false}
     */
    public boolean checkIndicesAction(String action) {
        return indices.check(action);
    }


    /**
     * For given index patterns and index privileges determines allowed privileges and creates an instance of {@link ResourcePrivilegesMap}
     * holding a map of resource to {@link ResourcePrivileges} where resource is index pattern and the map of index privilege to whether it
     * is allowed or not.
     *
     * @param checkForIndexPatterns check permission grants for the set of index patterns
     * @param allowRestrictedIndices if {@code true} then checks permission grants even for restricted indices by index matching
     * @param checkForPrivileges check permission grants for the set of index privileges
     * @return an instance of {@link ResourcePrivilegesMap}
     */
    public ResourcePrivilegesMap checkIndicesPrivileges(Set<String> checkForIndexPatterns, boolean allowRestrictedIndices,
                                                        Set<String> checkForPrivileges) {
        return indices.checkResourcePrivileges(checkForIndexPatterns, allowRestrictedIndices, checkForPrivileges);
    }

    /**
     * Check if cluster permissions allow for the given action in the context of given
     * authentication.
     *
     * @param action cluster action
     * @param request {@link TransportRequest}
     * @param authentication {@link Authentication}
     * @return {@code true} if action is allowed else returns {@code false}
     */
    public boolean checkClusterAction(String action, TransportRequest request, Authentication authentication) {
        return cluster.check(action, request, authentication);
    }

    /**
     * Check if cluster permissions grants the given cluster privilege
     *
     * @param clusterPrivilege cluster privilege
     * @return {@code true} if cluster privilege is allowed else returns {@code false}
     */
    public boolean grants(ClusterPrivilege clusterPrivilege) {
        return cluster.implies(clusterPrivilege.buildPermission(ClusterPermission.builder()).build());
    }

    /**
     * For a given application, checks for the privileges for resources and returns an instance of {@link ResourcePrivilegesMap} holding a
     * map of resource to {@link ResourcePrivileges} where the resource is application resource and the map of application privilege to
     * whether it is allowed or not.
     *
     * @param applicationName checks privileges for the provided application name
     * @param checkForResources check permission grants for the set of resources
     * @param checkForPrivilegeNames check permission grants for the set of privilege names
     * @param storedPrivileges stored {@link ApplicationPrivilegeDescriptor} for an application against which the access checks are
     * performed
     * @return an instance of {@link ResourcePrivilegesMap}
     */
    public ResourcePrivilegesMap checkApplicationResourcePrivileges(final String applicationName, Set<String> checkForResources,
                                                                    Set<String> checkForPrivilegeNames,
                                                                    Collection<ApplicationPrivilegeDescriptor> storedPrivileges) {
        return application.checkResourcePrivileges(applicationName, checkForResources, checkForPrivilegeNames, storedPrivileges);
    }

    /**
     * Returns whether at least one group encapsulated by this indices permissions is authorized to execute the
     * specified action with the requested indices/aliases. At the same time if field and/or document level security
     * is configured for any group also the allowed fields and role queries are resolved.
     */
    public IndicesAccessControl authorize(String action, Set<String> requestedIndicesOrAliases,
                                          Map<String, IndexAbstraction> aliasAndIndexLookup,
                                          FieldPermissionsCache fieldPermissionsCache) {
        Map<String, IndicesAccessControl.IndexAccessControl> indexPermissions = indices.authorize(
            action, requestedIndicesOrAliases, aliasAndIndexLookup, fieldPermissionsCache
        );

        // At least one role / indices permission set need to match with all the requested indices/aliases:
        boolean granted = true;
        for (Map.Entry<String, IndicesAccessControl.IndexAccessControl> entry : indexPermissions.entrySet()) {
            if (entry.getValue().isGranted() == false) {
                granted = false;
                break;
            }
        }
        return new IndicesAccessControl(granted, indexPermissions);
    }

    public Set<String> computeAuthorizedIndices(String action, boolean includeDataStreams, Metadata metadata) {
        // Clear if metadata version increases. Note this only works if the role is in active use.
        final long currentVersion = getCurrentMetadataVersion();
        final long newVersion = metadata.version();
        if (currentVersion < newVersion) {
            if (compareAndSetCurrentMetadataVersion(currentVersion, newVersion)) {
                logger.info("Update version of authorized indices from [{}] to [{}]", currentVersion, newVersion);
                // This is not thread safe, but we don't really need to care
                if (false == getAuthorizedIndicesCache().isEmpty()) {
                    logger.info("Clear authorized indices cache version for new version [{}]", newVersion);
                    getAuthorizedIndicesCache().clear();
                }
            }
        }

        // If role is superuser, actual action does not matter. So we use a marker for space efficiency
        final AuthorizedIndicesValue v = getAuthorizedIndicesCache().computeIfAbsent(
            getAuthorizedIndicesKey(action, metadata),
            k -> doComputeAuthorizedIndices(k, metadata));
        return includeDataStreams ? v.indicesAndAliasesAndDatastreams : v.indicesAndAliases;
    }

    private AuthorizedIndicesValue doComputeAuthorizedIndices(AuthorizedIndicesKey key, Metadata metadata) {
        logger.info(
            "Authorized indices cache: size [{}], computing for: [{}@{}] [{}] with key [{}]",
            getAuthorizedIndicesCache().size() + 1, getClass().getSimpleName(), System.identityHashCode(this),
            Arrays.toString(names), key);

        // No need to have predicate if role is superuser
        // Better way for determine superuser equivalent role?
        final Predicate<IndexAbstraction> predicate =
            (this == ReservedRolesStore.SUPERUSER_ROLE) ? null : allowedIndicesMatcher(key.normalizedAction);
        final SortedMap<String, IndexAbstraction> lookup = metadata.getIndicesLookup();
        Set<String> indicesAndAliases = new HashSet<>();
        Set<String> indicesAndAliasesAndDatastreams = new HashSet<>();
        // TODO: can this be done smarter? I think there are usually more indices/aliases in the cluster then indices defined a roles?
        for (IndexAbstraction indexAbstraction : lookup.values()) {
            if (predicate == null || predicate.test(indexAbstraction)) {
                indicesAndAliasesAndDatastreams.add(indexAbstraction.getName());
                if (indexAbstraction.getType() == IndexAbstraction.Type.DATA_STREAM) {
                    // add data stream and its backing indices for any authorized data streams
                    for (IndexMetadata indexMetadata : indexAbstraction.getIndices()) {
                        indicesAndAliasesAndDatastreams.add(indexMetadata.getIndex().getName());
                    }
                } else {
                    indicesAndAliases.add(indexAbstraction.getName());
                }
            }
        }
        logger.info("Number of authorized indices: [{}], [{}] with datastreams",
            indicesAndAliases.size(), indicesAndAliasesAndDatastreams.size());
        // Cache two sets with or without datastreams since an indicesRequest would normally request the list with datastreams first
        // and then request the list w/o datastreams when it fans out to the shards
        return new AuthorizedIndicesValue(indicesAndAliases, indicesAndAliasesAndDatastreams);
    }

    protected WeakHashMap<AuthorizedIndicesKey, AuthorizedIndicesValue> getAuthorizedIndicesCache() {
        return authorizedIndicesCache;
    }

    protected long getCurrentMetadataVersion() {
        return currentMetadataVersion.get();
    }

    protected boolean compareAndSetCurrentMetadataVersion(long expectedVersion, long newVersion) {
        return currentMetadataVersion.compareAndSet(expectedVersion, newVersion);
    }

    protected AuthorizedIndicesKey getAuthorizedIndicesKey(String action, Metadata metadata) {
        // Metadata version also changes for things not related to the list of indices.
        // For now we just use it as the best approximation
        return new AuthorizedIndicesKey(this == ReservedRolesStore.SUPERUSER_ROLE ? ANY_ACTION_MARKER : action, metadata.version());
    }

    public static class Builder {

        private final String[] names;
        private ClusterPermission cluster = ClusterPermission.NONE;
        private RunAsPermission runAs = RunAsPermission.NONE;
        private List<IndicesPermission.Group> groups = new ArrayList<>();
        private List<Tuple<ApplicationPrivilege, Set<String>>> applicationPrivs = new ArrayList<>();

        private Builder(String[] names) {
            this.names = names;
        }

        private Builder(RoleDescriptor rd, @Nullable FieldPermissionsCache fieldPermissionsCache) {
            this.names = new String[] { rd.getName() };
            cluster(Sets.newHashSet(rd.getClusterPrivileges()), Arrays.asList(rd.getConditionalClusterPrivileges()));
            groups.addAll(convertFromIndicesPrivileges(rd.getIndicesPrivileges(), fieldPermissionsCache));

            final RoleDescriptor.ApplicationResourcePrivileges[] applicationPrivileges = rd.getApplicationPrivileges();
            for (int i = 0; i < applicationPrivileges.length; i++) {
                applicationPrivs.add(convertApplicationPrivilege(rd.getName(), i, applicationPrivileges[i]));
            }

            String[] rdRunAs = rd.getRunAs();
            if (rdRunAs != null && rdRunAs.length > 0) {
                this.runAs(new Privilege(Sets.newHashSet(rdRunAs), rdRunAs));
            }
        }

        public Builder cluster(Set<String> privilegeNames, Iterable<ConfigurableClusterPrivilege> configurableClusterPrivileges) {
            ClusterPermission.Builder builder = ClusterPermission.builder();
            List<ClusterPermission> clusterPermissions = new ArrayList<>();
            if (privilegeNames.isEmpty() == false) {
                for (String name : privilegeNames) {
                    builder = ClusterPrivilegeResolver.resolve(name).buildPermission(builder);
                }
            }
            for (ConfigurableClusterPrivilege ccp : configurableClusterPrivileges) {
                builder = ccp.buildPermission(builder);
            }
            this.cluster = builder.build();
            return this;
        }

        public Builder runAs(Privilege privilege) {
            runAs = new RunAsPermission(privilege);
            return this;
        }

        public Builder add(IndexPrivilege privilege, String... indices) {
            groups.add(new IndicesPermission.Group(privilege, FieldPermissions.DEFAULT, null, false, indices));
            return this;
        }

        public Builder add(FieldPermissions fieldPermissions, Set<BytesReference> query, IndexPrivilege privilege,
                boolean allowRestrictedIndices, String... indices) {
            groups.add(new IndicesPermission.Group(privilege, fieldPermissions, query, allowRestrictedIndices, indices));
            return this;
        }

        public Builder addApplicationPrivilege(ApplicationPrivilege privilege, Set<String> resources) {
            applicationPrivs.add(new Tuple<>(privilege, resources));
            return this;
        }

        public Role build() {
            IndicesPermission indices = groups.isEmpty() ? IndicesPermission.NONE :
                new IndicesPermission(groups.toArray(new IndicesPermission.Group[groups.size()]));
            final ApplicationPermission applicationPermission
                = applicationPrivs.isEmpty() ? ApplicationPermission.NONE : new ApplicationPermission(applicationPrivs);
            return new Role(names, cluster, indices, applicationPermission, runAs);
        }

        static List<IndicesPermission.Group> convertFromIndicesPrivileges(RoleDescriptor.IndicesPrivileges[] indicesPrivileges,
                                                                          @Nullable FieldPermissionsCache fieldPermissionsCache) {
            List<IndicesPermission.Group> list = new ArrayList<>(indicesPrivileges.length);
            for (RoleDescriptor.IndicesPrivileges privilege : indicesPrivileges) {
                final FieldPermissions fieldPermissions;
                if (fieldPermissionsCache != null) {
                    fieldPermissions = fieldPermissionsCache.getFieldPermissions(privilege.getGrantedFields(), privilege.getDeniedFields());
                } else {
                    fieldPermissions = new FieldPermissions(
                        new FieldPermissionsDefinition(privilege.getGrantedFields(), privilege.getDeniedFields()));
                }
                final Set<BytesReference> query = privilege.getQuery() == null ? null : Collections.singleton(privilege.getQuery());
                list.add(new IndicesPermission.Group(IndexPrivilege.get(Sets.newHashSet(privilege.getPrivileges())), fieldPermissions,
                        query, privilege.allowRestrictedIndices(), privilege.getIndices()));
            }
            return list;
        }

        static Tuple<ApplicationPrivilege, Set<String>> convertApplicationPrivilege(String role, int index,
                                                                                    RoleDescriptor.ApplicationResourcePrivileges arp) {
            return new Tuple<>(new ApplicationPrivilege(arp.getApplication(),
                Sets.newHashSet(arp.getPrivileges()),
                arp.getPrivileges()
            ), Sets.newHashSet(arp.getResources()));
        }
    }

    protected static class AuthorizedIndicesKey {
        final Role role;
        final String normalizedAction;
        final long metadataVersion;

        AuthorizedIndicesKey(String action, long metadataVersion) {
            this(null, action, metadataVersion);
        }

        AuthorizedIndicesKey(Role role, String action, long metadataVersion) {
            this.role = role;
            // We don't really support granting specific sub actions. The builtin named privileges never do that
            final int subActionMarkerIndex = action.indexOf("[");
            this.normalizedAction = subActionMarkerIndex == -1 ? action : action.substring(0, subActionMarkerIndex);
            this.metadataVersion = metadataVersion;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            AuthorizedIndicesKey that = (AuthorizedIndicesKey) o;
            return metadataVersion == that.metadataVersion && Objects.equals(role, that.role) && Objects.equals(
                normalizedAction,
                that.normalizedAction);
        }

        @Override
        public int hashCode() {
            return Objects.hash(role, normalizedAction, metadataVersion);
        }

        @Override
        public String toString() {
            return "AuthorizedIndicesKey{" + "role="
                + (role == null ? null : role.getClass().getSimpleName() + "@" + System.identityHashCode(role))
                + ", normalizedAction='"
                + normalizedAction + '\'' + ", metadataVersion=" + metadataVersion + '}';
        }
    }

    protected static class AuthorizedIndicesValue {
        final Set<String> indicesAndAliases;
        final Set<String> indicesAndAliasesAndDatastreams;

        private AuthorizedIndicesValue(Set<String> indicesAndAliases, Set<String> indicesAndAliasesAndDatastreams) {
            this.indicesAndAliases = Set.copyOf(indicesAndAliases);
            if (indicesAndAliases.size() == indicesAndAliasesAndDatastreams.size()) {
                assert indicesAndAliases.equals(indicesAndAliasesAndDatastreams) : "two sets of indices must be identical";
                this.indicesAndAliasesAndDatastreams = this.indicesAndAliases;
            } else {
                this.indicesAndAliasesAndDatastreams = Set.copyOf(indicesAndAliasesAndDatastreams);
            }
        }
    }
}
