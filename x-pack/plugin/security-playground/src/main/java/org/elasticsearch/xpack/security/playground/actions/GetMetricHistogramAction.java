/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.actions;

import org.elasticsearch.action.ActionType;
import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.support.nodes.BaseNodeResponse;
import org.elasticsearch.action.support.nodes.BaseNodesRequest;
import org.elasticsearch.action.support.nodes.BaseNodesResponse;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContentFragment;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.security.playground.metric.HistogramMetric;

import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

public class GetMetricHistogramAction extends ActionType<GetMetricHistogramAction.Response> {

    public static final String NAME = "cluster:admin/xpack/security/playground/metric/histogram";
    public static final GetMetricHistogramAction INSTANCE = new GetMetricHistogramAction();

    public GetMetricHistogramAction() {
        super(NAME, Response::new);
    }

    public static class Request extends BaseNodesRequest<Request> {

        final String xOpaqueId;

        public Request() {
            this((String) null);
        }

        public Request(String xOpaqueId) {
            super((String[]) null);
            this.xOpaqueId = xOpaqueId;
        }

        public Request(StreamInput in) throws IOException {
            super(in);
            this.xOpaqueId = in.readOptionalString();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeOptionalString(xOpaqueId);
        }
    }

    public static class NodeRequest extends TransportRequest {

        final String xOpaqueId;

        public NodeRequest(StreamInput in) throws IOException {
            super(in);
            this.xOpaqueId = in.readOptionalString();
        }

        public NodeRequest(Request request) {
            this.xOpaqueId = request.xOpaqueId;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeOptionalString(xOpaqueId);
        }
    }

    public static class Response extends BaseNodesResponse<NodeResponse> implements ToXContentFragment {

        private final String masterNodeName;
        private final String localNodeName;
        private final long timestamp;
        private final String xOpaqueId;

        public Response(StreamInput in) throws IOException {
            super(in);
            this.masterNodeName = in.readString();
            this.localNodeName = in.readString();
            this.timestamp = in.readLong();
            this.xOpaqueId = in.readOptionalString();
        }

        public Response(
            ClusterName clusterName,
            List<NodeResponse> nodes,
            List<FailedNodeException> failures,
            String masterNodeName,
            String localNodeName,
            long timestamp,
            String xOpaqueId
        ) {
            super(clusterName, nodes, failures);
            this.masterNodeName = masterNodeName;
            this.localNodeName = localNodeName;
            this.timestamp = timestamp;
            this.xOpaqueId = xOpaqueId;
        }

        public String getMasterNodeName() {
            return masterNodeName;
        }

        public String getLocalNodeName() {
            return localNodeName;
        }

        public String getXOpaqueId() {
            return xOpaqueId;
        }

        @Override
        protected List<NodeResponse> readNodesFrom(StreamInput in) throws IOException {
            return in.readList(NodeResponse::new);
        }

        @Override
        protected void writeNodesTo(StreamOutput out, List<NodeResponse> nodes) throws IOException {
            out.writeList(nodes);
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeString(masterNodeName);
            out.writeString(localNodeName);
            out.writeLong(timestamp);
            out.writeOptionalString(xOpaqueId);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            final boolean groupByNodeName = params.paramAsBoolean("group_by_node_name", true);
            builder.field("master_node_name", masterNodeName);
            builder.field("node_name", localNodeName);
            builder.field("timestamp", timestamp);
            if (xOpaqueId != null) {
                builder.field("x_opaque_id", xOpaqueId);
            }
            builder.startObject("nodes");
            for (NodeResponse nodeResponse : getSortedNodes()) {
                if (nodeResponse.histograms.isEmpty() || nodeResponse.histograms.stream().allMatch(HistogramMetric::isZero)) {
                    continue;
                }
                if (groupByNodeName) {
                    builder.startObject(nodeResponse.getNode().getName());
                    builder.field("id", nodeResponse.getNode().getId());
                } else {
                    builder.startObject(nodeResponse.getNode().getId());
                    builder.field("name", nodeResponse.getNode().getName());
                }
                builder.startObject("metric");
                for (HistogramMetric histogram : nodeResponse.histograms) {
                    if (false == histogram.isZero()) {
                        histogram.toXContent(builder, params);
                    }
                }
                builder.endObject();
                builder.endObject();
            }
            builder.endObject();
            return builder;
        }

        private List<NodeResponse> getSortedNodes() {
            return getNodes().stream().sorted(Comparator.comparing(n -> n.getNode().getName())).collect(Collectors.toUnmodifiableList());
        }
    }

    public static class NodeResponse extends BaseNodeResponse {
        private final List<HistogramMetric> histograms;

        public NodeResponse(StreamInput in) throws IOException {
            super(in);
            histograms = in.readList(HistogramMetric::new);
        }

        public NodeResponse(DiscoveryNode node, List<HistogramMetric> histograms) {
            super(node);
            this.histograms = histograms;
        }

        public List<HistogramMetric> getHistograms() {
            return List.copyOf(histograms);
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeList(histograms);
        }
    }
}
