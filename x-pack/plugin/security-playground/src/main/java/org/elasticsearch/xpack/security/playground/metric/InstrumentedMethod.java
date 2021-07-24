/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.metric;

import java.util.Locale;

public enum InstrumentedMethod {

    RESOLVE_AUTHORIZATION_INFO("resolveAuthorizationInfo"),
    AUTHORIZE_RUN_AS("authorizeRunAs"),
    AUTHORIZE_CLUSTER_ACTION("authorizeClusterAction"),
    AUTHORIZE_INDEX_ACTION("authorizeIndexAction"),
    LOAD_AUTHORIZED_INDICES("loadAuthorizedIndices"),
    ROLE_ALLOWED_INDICES_MATCHER("roleAllowedIndicesMatcher"),
    ROLE_ALLOWED_ACTIONS_MATCHER("roleAllowedActionsMatcher"),
    ROLE_CHECK_RUN_AS("roleCheckRunAs"),
    ROLE_CHECK_INDICES_ACTION("roleCheckIndicesAction"),
    ROLE_CHECK_CLUSTER_ACTION("roleCheckClusterAction"),
    ROLE_AUTHORIZE("roleAuthorize"),
    IAAR_RESOLVE("iaarResolve");

    private final String methodName;

    InstrumentedMethod(String methodName) {
        this.methodName = methodName;
    }

    @Override
    public String toString() {
        return methodName;
    }

    public String jsonName() {
        return name().toLowerCase(Locale.ROOT);
    }
}
