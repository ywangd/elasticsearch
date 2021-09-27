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
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.security.playground.metric.AuthorizationMetrics;

import java.io.IOException;
import java.util.List;

public class TransportGetMetricInstantAction extends TransportNodesAction<
    GetMetricInstantAction.Request,
    GetMetricInstantAction.Response,
    GetMetricInstantAction.NodeRequest,
    GetMetricInstantAction.NodeResponse> {

    @Inject
    public TransportGetMetricInstantAction(
        ThreadPool threadPool,
        ClusterService clusterService,
        TransportService transportService,
        ActionFilters actionFilters
    ) {
        super(
            GetMetricInstantAction.NAME,
            threadPool,
            clusterService,
            transportService,
            actionFilters,
            GetMetricInstantAction.Request::new,
            GetMetricInstantAction.NodeRequest::new,
            ThreadPool.Names.MANAGEMENT,
            GetMetricInstantAction.NodeResponse.class
        );
    }

    @Override
    protected GetMetricInstantAction.Response newResponse(
        GetMetricInstantAction.Request request,
        List<GetMetricInstantAction.NodeResponse> nodeResponses,
        List<FailedNodeException> failures
    ) {
        return new GetMetricInstantAction.Response(
            clusterService.getClusterName(),
            nodeResponses,
            failures,
            clusterService.state().nodes().getMasterNode().getName(),
            clusterService.getNodeName(),
            request.elapsed,
            System.nanoTime()
        );
    }

    @Override
    protected GetMetricInstantAction.NodeRequest newNodeRequest(GetMetricInstantAction.Request request) {
        return new GetMetricInstantAction.NodeRequest(request);
    }

    @Override
    protected GetMetricInstantAction.NodeResponse newNodeResponse(StreamInput in, DiscoveryNode node) throws IOException {
        return new GetMetricInstantAction.NodeResponse(in);
    }

    @Override
    protected GetMetricInstantAction.NodeResponse nodeOperation(GetMetricInstantAction.NodeRequest request, Task task) {
        return new GetMetricInstantAction.NodeResponse(
            clusterService.localNode(),
            AuthorizationMetrics.getInstantaneousMetric(request.xOpaqueId)
        );
    }
}
