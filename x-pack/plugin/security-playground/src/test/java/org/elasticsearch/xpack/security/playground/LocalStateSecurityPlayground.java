/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.xpack.core.security.authz.AuthorizationEngine;
import org.elasticsearch.xpack.security.LocalStateSecurity;
import org.elasticsearch.xpack.security.Security;
import org.elasticsearch.xpack.security.playground.authz.InstrumentedAuthorizationEngine;
import org.elasticsearch.xpack.security.playground.authz.SecurityPlaygroundPluginSecurityExtension;

import java.nio.file.Path;
import java.util.List;

public class LocalStateSecurityPlayground extends LocalStateSecurity {

    public LocalStateSecurityPlayground(Settings settings, Path configPath) throws Exception {
        super(settings, configPath);
        final Plugin securityPlugin = plugins.stream().filter(p -> p instanceof Security).findFirst().orElseThrow();

        ((Security) securityPlugin).loadExtensions(new ExtensionLoader() {
            @SuppressWarnings("unchecked")
            @Override
            public <T> List<T> loadExtensions(Class<T> extensionPointType) {
                return List.of((T) new SecurityPlaygroundPluginSecurityExtension() {
                    @Override
                    public AuthorizationEngine getAuthorizationEngine(Settings settings) {
                        return new InstrumentedAuthorizationEngine(settings, threadContext) {
                            @Override
                            protected void maybeInjectClasspath() {
                                // No need to inject classpath because test loads all plugins with the same AppClassloader
                            }
                        };
                    }
                });
            }
        });
        LocalStateSecurityPlayground thisVar = this;
        plugins.add(new SecurityPlaygroundPlugin(settings, configPath) {
            @Override
            protected XPackLicenseState getLicenseState() {
                return thisVar.getLicenseState();
            }
        });
    }
}
