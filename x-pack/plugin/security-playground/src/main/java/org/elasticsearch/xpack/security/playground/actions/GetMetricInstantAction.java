/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.actions;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionType;
import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.support.nodes.BaseNodeResponse;
import org.elasticsearch.action.support.nodes.BaseNodesRequest;
import org.elasticsearch.action.support.nodes.BaseNodesResponse;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.rest.action.RestActions;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.security.playground.metric.InstantMetric;

import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

public class GetMetricInstantAction extends ActionType<GetMetricInstantAction.Response> {

    public static final String NAME = "cluster:admin/xpack/security/playground/metric/instant";
    public static final GetMetricInstantAction INSTANCE = new GetMetricInstantAction();

    public GetMetricInstantAction() {
        super(NAME, Response::new);
    }

    public static class Request extends BaseNodesRequest<GetMetricInstantAction.Request> {

        final String xOpaqueId;
        final long elapsed;

        public Request(String xOpaqueId, long elapsed) {
            super((String[]) null);
            this.xOpaqueId = xOpaqueId;
            this.elapsed = elapsed;
        }

        public Request(StreamInput in) throws IOException {
            super(in);
            this.xOpaqueId = in.readString();
            this.elapsed = in.readLong();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeString(xOpaqueId);
            out.writeLong(elapsed);
        }
    }

    public static class NodeRequest extends TransportRequest {

        final String xOpaqueId;

        public NodeRequest(StreamInput in) throws IOException {
            super(in);
            this.xOpaqueId = in.readString();
        }

        public NodeRequest(GetMetricInstantAction.Request request) {
            this.xOpaqueId = request.xOpaqueId;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeString(xOpaqueId);
        }
    }

    public static class Response extends BaseNodesResponse<GetMetricInstantAction.NodeResponse> implements ToXContent {

        private final String masterNodeName;
        private final String localNodeName;
        private final long timestamp;
        private final long elapsed;

        public Response(StreamInput in) throws IOException {
            super(in);
            this.masterNodeName = in.readString();
            this.localNodeName = in.readString();
            this.timestamp = in.readLong();
            this.elapsed = in.readLong();
        }

        public Response(
            ClusterName clusterName,
            List<GetMetricInstantAction.NodeResponse> nodes,
            List<FailedNodeException> failures,
            String masterNodeName,
            String localNodeName,
            long elapsed,
            long timestamp
        ) {
            super(clusterName, nodes, failures);
            this.masterNodeName = masterNodeName;
            this.localNodeName = localNodeName;
            this.timestamp = timestamp;
            this.elapsed = elapsed;
        }

        @Override
        protected List<GetMetricInstantAction.NodeResponse> readNodesFrom(StreamInput in) throws IOException {
            return in.readList(GetMetricInstantAction.NodeResponse::new);
        }

        @Override
        protected void writeNodesTo(StreamOutput out, List<GetMetricInstantAction.NodeResponse> nodes) throws IOException {
            out.writeList(nodes);
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeString(masterNodeName);
            out.writeString(localNodeName);
            out.writeLong(timestamp);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            final boolean groupByNodeName = params.paramAsBoolean("group_by_node_name", true);
            builder.startObject();
            RestActions.buildNodesHeader(builder, params, this);
            builder.field("cluster_name", getClusterName().value());
            builder.field("master_node_name", masterNodeName);
            builder.field("node_name", localNodeName);
            builder.field("elapsed", elapsed);
            builder.field("timestamp", timestamp);
            builder.startObject("nodes");
            for (GetMetricInstantAction.NodeResponse nodeResponse : getSortedNodes()) {
                if (nodeResponse.metricValue != null) {
                    if (groupByNodeName) {
                        builder.startObject(nodeResponse.getNode().getName());
                        builder.field("id", nodeResponse.getNode().getId());
                    } else {
                        builder.startObject(nodeResponse.getNode().getId());
                        builder.field("name", nodeResponse.getNode().getName());
                    }
                    nodeResponse.metricValue.innerToXContent(builder, params);
                    builder.endObject();
                }
            }
            builder.endObject();
            builder.endObject();
            return builder;
        }

        private List<GetMetricInstantAction.NodeResponse> getSortedNodes() {
            return getNodes().stream().sorted(Comparator.comparing(n -> n.getNode().getName())).collect(Collectors.toUnmodifiableList());
        }

        @Override
        public String toString() {
            try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
                toXContent(builder, EMPTY_PARAMS);
                return Strings.toString(builder);
            } catch (Exception e) {
                throw new ElasticsearchException("Failed to build xcontent", e);
            }
        }
    }

    public static class NodeResponse extends BaseNodeResponse {

        final InstantMetric metricValue;

        public NodeResponse(StreamInput in) throws IOException {
            super(in);
            if (in.readBoolean()) {
                this.metricValue = new InstantMetric(in);
            } else {
                this.metricValue = null;
            }
        }

        public NodeResponse(DiscoveryNode node, InstantMetric metricValue) {
            super(node);
            this.metricValue = metricValue;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            if (metricValue == null) {
                out.writeBoolean(false);
            } else {
                out.writeBoolean(true);
                metricValue.writeTo(out);
            }
        }
    }
}
