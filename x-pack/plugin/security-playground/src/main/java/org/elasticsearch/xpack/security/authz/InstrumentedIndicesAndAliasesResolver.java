/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz;

import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authz.ResolvedIndices;

import java.util.Set;
import java.util.function.BiFunction;

public class InstrumentedIndicesAndAliasesResolver extends IndicesAndAliasesResolver {

    private final BiFunction<String, Integer, Runnable> startMetricFunc;
    private final BiFunction<String, Metadata, Metadata> metadataInjectionFunc;

    public InstrumentedIndicesAndAliasesResolver(
        Settings settings,
        ClusterService clusterService,
        IndexNameExpressionResolver resolver,
        BiFunction<String, Integer, Runnable> startMetricFunc,
        BiFunction<String, Metadata, Metadata> metadataInjectionFunc
    ) {
        super(settings, clusterService, resolver);
        this.startMetricFunc = startMetricFunc;
        this.metadataInjectionFunc = metadataInjectionFunc;
    }

    @Override
    public ResolvedIndices resolve(String action, TransportRequest request, Metadata metadata, Set<String> authorizedIndices) {
        final Runnable stopMetricFunc = startMetricFunc.apply(action, System.identityHashCode(request));
        try {
            return super.resolve(action, request, metadataInjectionFunc.apply(action, metadata), authorizedIndices);
        } finally {
            stopMetricFunc.run();
        }
    }
}
