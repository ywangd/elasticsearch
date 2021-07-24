/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz;

import org.elasticsearch.xpack.core.security.authz.AuthorizationEngine.AuthorizationInfo;
import org.elasticsearch.xpack.core.security.authz.permission.InstrumentedRole;
import org.elasticsearch.xpack.core.security.authz.permission.Role;
import org.elasticsearch.xpack.security.authz.RBACEngine.RBACAuthorizationInfo;

import java.util.function.Function;

public class RBACEngineAuthorizationInfoBridge {

    public static AuthorizationInfo bridge(AuthorizationInfo authorizationInfo, Function<String, Runnable> startMetricFunc) {
        final RBACAuthorizationInfo rbacAuthorizationInfo = (RBACAuthorizationInfo) authorizationInfo;

        final Role role = rbacAuthorizationInfo.getRole();
        final Role authenticatedRole = rbacAuthorizationInfo.getAuthenticatedUserAuthorizationInfo().getRole();

        return new RBACAuthorizationInfo(new InstrumentedRole(role, startMetricFunc), role == authenticatedRole ? null : authenticatedRole);

    }
}
