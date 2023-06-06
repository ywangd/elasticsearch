/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authz.permission;

import org.apache.lucene.util.automaton.Automaton;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptorsIntersection;
import org.elasticsearch.xpack.core.security.authz.accesscontrol.IndicesAccessControl;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilege;
import org.elasticsearch.xpack.core.security.support.Automatons;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class UnionRole implements Role {

    private final List<SimpleRole> roles;

    public UnionRole(List<SimpleRole> roles) {
        this.roles = List.copyOf(roles);
    }

    @Override
    public String[] names() {
        return roles.stream().map(Role::names).flatMap(Arrays::stream).toArray(String[]::new);
    }

    @Override
    public ClusterPermission cluster() {
        throw new UnsupportedOperationException("cannot retrieve cluster permission on union role");
    }

    @Override
    public IndicesPermission indices() {
        throw new UnsupportedOperationException("cannot retrieve indices permission on union role");
    }

    @Override
    public RemoteIndicesPermission remoteIndices() {
        throw new UnsupportedOperationException("cannot retrieve remote indices permission on union role");
    }

    @Override
    public ApplicationPermission application() {
        throw new UnsupportedOperationException("cannot retrieve application permission on union role");
    }

    @Override
    public RunAsPermission runAs() {
        throw new UnsupportedOperationException("cannot retrieve run_as permission on union role");
    }

    @Override
    public boolean hasFieldOrDocumentLevelSecurity() {
        return roles.stream().anyMatch(Role::hasFieldOrDocumentLevelSecurity);
    }

    @Override
    public IndicesPermission.IsResourceAuthorizedPredicate allowedIndicesMatcher(String action) {
        return roles.stream()
            .map(role -> role.allowedIndicesMatcher(action))
            .reduce(IndicesPermission.IsResourceAuthorizedPredicate::or)
            .orElseThrow();
    }

    @Override
    public Automaton allowedActionsMatcher(String index) {
        return Automatons.unionAndMinimize(roles.stream().map(role -> role.allowedActionsMatcher(index)).toList());
    }

    @Override
    public boolean checkRunAs(String runAsName) {
        return roles.stream().anyMatch(role -> role.checkRunAs(runAsName));
    }

    @Override
    public boolean checkIndicesAction(String action) {
        return roles.stream().anyMatch(role -> role.checkIndicesAction(action));
    }

    @Override
    public boolean checkIndicesPrivileges(
        Set<String> checkForIndexPatterns,
        boolean allowRestrictedIndices,
        Set<String> checkForPrivileges,
        ResourcePrivilegesMap.Builder resourcePrivilegesMapBuilder
    ) {
        return roles.stream()
            .anyMatch(
                role -> role.checkIndicesPrivileges(
                    checkForIndexPatterns,
                    allowRestrictedIndices,
                    checkForPrivileges,
                    resourcePrivilegesMapBuilder
                )
            );
    }

    @Override
    public boolean checkClusterAction(String action, TransportRequest request, Authentication authentication) {
        return roles.stream().anyMatch(role -> role.checkClusterAction(action, request, authentication));
    }

    @Override
    public boolean grants(ClusterPrivilege clusterPrivilege) {
        return roles.stream().anyMatch(role -> role.grants(clusterPrivilege));
    }

    @Override
    public boolean checkApplicationResourcePrivileges(
        String applicationName,
        Set<String> checkForResources,
        Set<String> checkForPrivilegeNames,
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges,
        ResourcePrivilegesMap.Builder resourcePrivilegesMapBuilder
    ) {
        return roles.stream()
            .anyMatch(
                role -> role.checkApplicationResourcePrivileges(
                    applicationName,
                    checkForResources,
                    checkForPrivilegeNames,
                    storedPrivileges,
                    resourcePrivilegesMapBuilder
                )
            );
    }

    @Override
    public IndicesAccessControl authorize(
        String action,
        Set<String> requestedIndicesOrAliases,
        Map<String, IndexAbstraction> aliasAndIndexLookup,
        FieldPermissionsCache fieldPermissionsCache
    ) {
        return roles.stream()
            .map(role -> role.authorize(action, requestedIndicesOrAliases, aliasAndIndexLookup, fieldPermissionsCache))
            .reduce(IndicesAccessControl::or)
            .orElseThrow();
    }

    @Override
    public RoleDescriptorsIntersection getRoleDescriptorsIntersectionForRemoteCluster(String remoteClusterAlias) {
        final Set<RoleDescriptor> roleDescriptors = roles.stream()
            .map(role -> role.getRoleDescriptorsIntersectionForRemoteCluster(remoteClusterAlias))
            .filter(roleDescriptorsIntersection -> false == roleDescriptorsIntersection.isEmpty())
            .map(roleDescriptorsIntersection -> roleDescriptorsIntersection.roleDescriptorsList().iterator().next())
            .flatMap(Set::stream)
            .collect(Collectors.toUnmodifiableSet());
        return new RoleDescriptorsIntersection(List.of(roleDescriptors));
    }

    @Override
    public Role forRestriction(RoleDescriptor.Restriction restriction) {
        final Builder builder = builder();
        roles.stream().map(role -> role.forRestriction(restriction)).forEach(role -> {
            assert role instanceof SimpleRole;
            builder.addRole((SimpleRole) role);
        });
        return builder.build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final List<SimpleRole> roles = new ArrayList<>();

        public Builder addRole(SimpleRole role) {
            roles.add(role);
            return this;
        }

        public Role build() {
            if (roles.isEmpty()) {
                return Role.EMPTY;
            } else if (roles.size() == 1) {
                return roles.get(0);
            } else {
                return new UnionRole(roles);
            }
        }
    }
}
