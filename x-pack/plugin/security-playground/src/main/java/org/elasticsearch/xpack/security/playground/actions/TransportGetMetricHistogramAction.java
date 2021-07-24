/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.actions;

import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.nodes.TransportNodesAction;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.security.playground.metric.AuthorizationMetrics;

import java.io.IOException;
import java.util.List;

public class TransportGetMetricHistogramAction extends TransportNodesAction<
    GetMetricHistogramAction.Request,
    GetMetricHistogramAction.Response,
    GetMetricHistogramAction.NodeRequest,
    GetMetricHistogramAction.NodeResponse> {

    @Inject
    public TransportGetMetricHistogramAction(
        ThreadPool threadPool,
        ClusterService clusterService,
        TransportService transportService,
        ActionFilters actionFilters
    ) {
        super(
            GetMetricHistogramAction.NAME,
            threadPool,
            clusterService,
            transportService,
            actionFilters,
            GetMetricHistogramAction.Request::new,
            GetMetricHistogramAction.NodeRequest::new,
            ThreadPool.Names.MANAGEMENT,
            GetMetricHistogramAction.NodeResponse.class
        );
    }

    @Override
    protected GetMetricHistogramAction.Response newResponse(
        GetMetricHistogramAction.Request request,
        List<GetMetricHistogramAction.NodeResponse> nodeResponses,
        List<FailedNodeException> failures
    ) {
        return new GetMetricHistogramAction.Response(
            clusterService.getClusterName(),
            nodeResponses,
            failures,
            clusterService.state().nodes().getMasterNode().getName(),
            clusterService.getNodeName(),
            System.nanoTime(),
            request.xOpaqueId
        );
    }

    @Override
    protected GetMetricHistogramAction.NodeRequest newNodeRequest(GetMetricHistogramAction.Request request) {
        return new GetMetricHistogramAction.NodeRequest(request);
    }

    @Override
    protected GetMetricHistogramAction.NodeResponse newNodeResponse(StreamInput in) throws IOException {
        return new GetMetricHistogramAction.NodeResponse(in);
    }

    @Override
    protected GetMetricHistogramAction.NodeResponse nodeOperation(GetMetricHistogramAction.NodeRequest request, Task task) {
        return new GetMetricHistogramAction.NodeResponse(
            clusterService.localNode(),
            AuthorizationMetrics.getMetricHistograms(request.xOpaqueId)
        );
    }
}
