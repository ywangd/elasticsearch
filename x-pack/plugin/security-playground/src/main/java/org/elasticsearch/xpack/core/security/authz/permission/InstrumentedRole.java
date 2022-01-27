/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authz.permission;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.apache.lucene.util.automaton.Automaton;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.accesscontrol.IndicesAccessControl;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilege;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;

public class InstrumentedRole implements Role {

    private static final Logger logger = LogManager.getLogger(InstrumentedRole.class);

    private final Role delegate;
    private final Function<String, Runnable> startMetricFunc;

    public InstrumentedRole(Role role, Function<String, Runnable> startMetricFunc) {
        this.delegate = role;
        this.startMetricFunc = startMetricFunc;
    }

    @Override
    public String[] names() {
        return delegate.names();
    }

    @Override
    public ClusterPermission cluster() {
        return delegate.cluster();
    }

    @Override
    public IndicesPermission indices() {
        return delegate.indices();
    }

    @Override
    public ApplicationPermission application() {
        return delegate.application();
    }

    @Override
    public RunAsPermission runAs() {
        return delegate.runAs();
    }

    @Override
    public boolean hasFieldOrDocumentLevelSecurity() {
        return delegate.hasFieldOrDocumentLevelSecurity();
    }

    @Override
    public Predicate<IndexAbstraction> allowedIndicesMatcher(String action) {
        // TODO: injectable matcher
        final Runnable stopMetric = startMetricFunc.apply("ROLE_ALLOWED_INDICES_MATCHER");
        try {
            return delegate.allowedIndicesMatcher(action);
        } finally {
            stopMetric.run();
        }
    }

    @Override
    public Automaton allowedActionsMatcher(String index) {
        final Runnable stopMetric = startMetricFunc.apply("ROLE_ALLOWED_ACTIONS_MATCHER");
        try {
            return delegate.allowedActionsMatcher(index);
        } finally {
            stopMetric.run();
        }
    }

    @Override
    public boolean checkRunAs(String runAsName) {
        final Runnable stopMetric = startMetricFunc.apply("ROLE_CHECK_RUN_AS");
        try {
            return delegate.checkRunAs(runAsName);
        } finally {
            stopMetric.run();
        }
    }

    @Override
    public boolean checkIndicesAction(String action) {
        final Runnable stopMetric = startMetricFunc.apply("ROLE_CHECK_INDICES_ACTION");
        try {
            // TODO: always allow _security_playground/index
            return delegate.checkIndicesAction(action);
        } finally {
            stopMetric.run();
        }
    }

    @Override
    public ResourcePrivilegesMap checkIndicesPrivileges(
        Set<String> checkForIndexPatterns,
        boolean allowRestrictedIndices,
        Set<String> checkForPrivileges
    ) {
        return null;
    }

    @Override
    public boolean checkClusterAction(String action, TransportRequest request, Authentication authentication) {
        final Runnable stopMetric = startMetricFunc.apply("ROLE_CHECK_CLUSTER_ACTION");
        try {
            return delegate.checkClusterAction(action, request, authentication);
        } finally {
            stopMetric.run();
        }
    }

    @Override
    public boolean grants(ClusterPrivilege clusterPrivilege) {
        return false;
    }

    @Override
    public ResourcePrivilegesMap checkApplicationResourcePrivileges(
        String applicationName,
        Set<String> checkForResources,
        Set<String> checkForPrivilegeNames,
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges
    ) {
        return null;
    }

    @Override
    public IndicesAccessControl authorize(
        String action,
        Set<String> requestedIndicesOrAliases,
        Map<String, IndexAbstraction> aliasAndIndexLookup,
        FieldPermissionsCache fieldPermissionsCache
    ) {
        final Runnable stopMetric = startMetricFunc.apply("ROLE_AUTHORIZE");
        logger.trace(
            () -> new ParameterizedMessage(
                "[ROLE_AUTHORIZE] computing IndicesAccessControl for [{}] names",
                requestedIndicesOrAliases.size()
            )
        );
        try {
            return delegate.authorize(action, requestedIndicesOrAliases, aliasAndIndexLookup, fieldPermissionsCache);
        } finally {
            stopMetric.run();
        }
    }
}
