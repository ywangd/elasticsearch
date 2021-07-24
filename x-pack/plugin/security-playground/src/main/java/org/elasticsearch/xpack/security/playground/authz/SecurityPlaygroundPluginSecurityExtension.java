/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.authz;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.xpack.core.security.SecurityExtension;
import org.elasticsearch.xpack.core.security.authz.AuthorizationEngine;
import org.elasticsearch.xpack.core.security.authz.store.RoleRetrievalResult;

import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;

public class SecurityPlaygroundPluginSecurityExtension implements SecurityExtension {

    protected ThreadContext threadContext;

    @Override
    public List<BiConsumer<Set<String>, ActionListener<RoleRetrievalResult>>> getRolesProviders(SecurityComponents components) {
        threadContext = components.threadPool().getThreadContext();
        return List.of();
    }

    @Override
    public AuthorizationEngine getAuthorizationEngine(Settings settings) {
        return new InstrumentedAuthorizationEngine(settings, threadContext);
    }
}
