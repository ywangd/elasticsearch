/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.IndexScopedSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.SettingsFilter;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.NodeEnvironment;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.repositories.RepositoriesService;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.watcher.ResourceWatcherService;
import org.elasticsearch.xcontent.NamedXContentRegistry;
import org.elasticsearch.xpack.core.XPackPlugin;
import org.elasticsearch.xpack.core.XPackSettings;
import org.elasticsearch.xpack.security.playground.actions.GetMetricHistogramAction;
import org.elasticsearch.xpack.security.playground.actions.GetMetricInstantAction;
import org.elasticsearch.xpack.security.playground.actions.RestGetMetricHistogramAction;
import org.elasticsearch.xpack.security.playground.actions.RestMetricProxyAction;
import org.elasticsearch.xpack.security.playground.actions.RestSPClusterAction;
import org.elasticsearch.xpack.security.playground.actions.RestSPIndexAction;
import org.elasticsearch.xpack.security.playground.actions.SPClusterAction;
import org.elasticsearch.xpack.security.playground.actions.SPIndexAction;
import org.elasticsearch.xpack.security.playground.actions.TransportGetMetricHistogramAction;
import org.elasticsearch.xpack.security.playground.actions.TransportGetMetricInstantAction;
import org.elasticsearch.xpack.security.playground.actions.TransportSPClusterAction;
import org.elasticsearch.xpack.security.playground.actions.TransportSPIndexAction;
import org.elasticsearch.xpack.security.playground.simulation.FileIndicesStatusProvider;

import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.elasticsearch.xpack.security.playground.RestClientComponent.PROXY_CLIENT_SOCKET_TIMEOUT;

public class SecurityPlaygroundPlugin extends Plugin implements ActionPlugin {

    public static final Setting<Boolean> INSTRUMENTED_ALL_ENABLED = Setting.boolSetting(
        "xpack.security.playground.instrumentation.all.enabled",
        true,
        Setting.Property.NodeScope
    );

    public static final Setting<Boolean> INSTRUMENTED_ROLE_ENABLED = Setting.boolSetting(
        "xpack.security.playground.instrumentation.role.enabled",
        settings -> INSTRUMENTED_ALL_ENABLED.get(settings).toString(),
        Setting.Property.NodeScope
    );

    public static final Setting<Boolean> INSTRUMENTED_RELEVANT_INTERNAL_ACTIONS_ENABLED = Setting.boolSetting(
        "xpack.security.playground.instrumentation.relevant_internal_actions.enabled",
        settings -> INSTRUMENTED_ALL_ENABLED.get(settings).toString(),
        Setting.Property.NodeScope
    );

    public static final Setting<Boolean> INSTRUMENTED_INDICES_AND_ALIASES_RESOLVER_ENABLED = Setting.boolSetting(
        "xpack.security.playground.instrumentation.indices_and_aliases_resolver.enabled",
        settings -> INSTRUMENTED_ALL_ENABLED.get(settings).toString(),
        Setting.Property.NodeScope
    );

    public static final AtomicReference<ClusterService> CLUSTER_SERVICE_REF = new AtomicReference<>();
    public static final AtomicReference<IndexNameExpressionResolver> INDEX_NAME_EXPRESSION_RESOLVER_REF = new AtomicReference<>();

    private final boolean enabled;
    private final RestClientComponent restClientComponent;

    public SecurityPlaygroundPlugin(Settings settings, final Path configPath) {
        this.enabled = XPackSettings.SECURITY_ENABLED.get(settings);
        restClientComponent = new RestClientComponent(settings);
    }

    @Override
    public Collection<Object> createComponents(
        Client client,
        ClusterService clusterService,
        ThreadPool threadPool,
        ResourceWatcherService resourceWatcherService,
        ScriptService scriptService,
        NamedXContentRegistry xContentRegistry,
        Environment environment,
        NodeEnvironment nodeEnvironment,
        NamedWriteableRegistry namedWriteableRegistry,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<RepositoriesService> repositoriesServiceSupplier
    ) {
        if (false == enabled) {
            return List.of();
        }
        CLUSTER_SERVICE_REF.set(clusterService);
        INDEX_NAME_EXPRESSION_RESOLVER_REF.set(indexNameExpressionResolver);
        return List.of(restClientComponent, new FileIndicesStatusProvider(environment, resourceWatcherService));
    }

    @Override
    public List<RestHandler> getRestHandlers(
        Settings settings,
        RestController restController,
        ClusterSettings clusterSettings,
        IndexScopedSettings indexScopedSettings,
        SettingsFilter settingsFilter,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<DiscoveryNodes> nodesInCluster
    ) {
        if (false == enabled) {
            return List.of();
        }
        return List.of(
            new RestSPClusterAction(settings, getLicenseState()),
            new RestSPIndexAction(settings, getLicenseState()),
            new RestMetricProxyAction(settings, getLicenseState(), restClientComponent),
            new RestGetMetricHistogramAction(settings, getLicenseState())
        );
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        if (false == enabled) {
            return List.of();
        }
        return List.of(
            new ActionHandler<>(SPClusterAction.INSTANCE, TransportSPClusterAction.class),
            new ActionHandler<>(SPIndexAction.INSTANCE, TransportSPIndexAction.class),
            new ActionHandler<>(GetMetricInstantAction.INSTANCE, TransportGetMetricInstantAction.class),
            new ActionHandler<>(GetMetricHistogramAction.INSTANCE, TransportGetMetricHistogramAction.class)
        );
    }

    @Override
    public List<Setting<?>> getSettings() {
        return List.of(
            INSTRUMENTED_ALL_ENABLED,
            INSTRUMENTED_ROLE_ENABLED,
            INSTRUMENTED_RELEVANT_INTERNAL_ACTIONS_ENABLED,
            INSTRUMENTED_INDICES_AND_ALIASES_RESOLVER_ENABLED,
            PROXY_CLIENT_SOCKET_TIMEOUT
        );
    }

    protected XPackLicenseState getLicenseState() {
        return XPackPlugin.getSharedLicenseState();
    }
}
