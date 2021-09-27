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

import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;

public class InstrumentedRole extends Role {

    private static final Logger logger = LogManager.getLogger(InstrumentedRole.class);

    private final Function<String, Runnable> startMetricFunc;

    public InstrumentedRole(Role role, Function<String, Runnable> startMetricFunc) {
        super(role.names(), role.cluster(), role.indices(), role.application(), role.runAs());
        this.startMetricFunc = startMetricFunc;
    }

    @Override
    public Predicate<IndexAbstraction> allowedIndicesMatcher(String action) {
        // TODO: injectable matcher
        final Runnable stopMetric = startMetricFunc.apply("ROLE_ALLOWED_INDICES_MATCHER");
        try {
            return super.allowedIndicesMatcher(action);
        } finally {
            stopMetric.run();
        }
    }

    @Override
    public Automaton allowedActionsMatcher(String index) {
        final Runnable stopMetric = startMetricFunc.apply("ROLE_ALLOWED_ACTIONS_MATCHER");
        try {
            return super.allowedActionsMatcher(index);
        } finally {
            stopMetric.run();
        }
    }

    @Override
    public boolean checkRunAs(String runAsName) {
        final Runnable stopMetric = startMetricFunc.apply("ROLE_CHECK_RUN_AS");
        try {
            return super.checkRunAs(runAsName);
        } finally {
            stopMetric.run();
        }
    }

    @Override
    public boolean checkIndicesAction(String action) {
        final Runnable stopMetric = startMetricFunc.apply("ROLE_CHECK_INDICES_ACTION");
        try {
            // TODO: always allow _security_playground/index
            return super.checkIndicesAction(action);
        } finally {
            stopMetric.run();
        }
    }

    @Override
    public boolean checkClusterAction(String action, TransportRequest request, Authentication authentication) {
        final Runnable stopMetric = startMetricFunc.apply("ROLE_CHECK_CLUSTER_ACTION");
        try {
            return super.checkClusterAction(action, request, authentication);
        } finally {
            stopMetric.run();
        }
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
            return super.authorize(action, requestedIndicesOrAliases, aliasAndIndexLookup, fieldPermissionsCache);
        } finally {
            stopMetric.run();
        }
    }
}
