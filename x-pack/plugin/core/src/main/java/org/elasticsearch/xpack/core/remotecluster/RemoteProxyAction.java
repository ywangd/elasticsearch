/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.remotecluster;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionListenerResponseHandler;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.ActionType;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.client.internal.node.NodeClient;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.NamedWriteableAwareStreamInput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.RequestHandlerRegistry;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportService;

import java.io.IOException;
import java.io.UncheckedIOException;

public class RemoteProxyAction extends ActionType<RemoteProxyAction.RemoteProxyResponse> {
    public static final RemoteProxyAction INSTANCE = new RemoteProxyAction();
    public static final String NAME = "cluster:admin/remote_cluster/relay";

    public RemoteProxyAction() {
        super(NAME, RemoteProxyResponse::new);
    }

    public static class RemoteProxyRequest extends ActionRequest {

        private final String action;
        private final BytesReference payload;
        private final DiscoveryNode node;

        public RemoteProxyRequest(String action, BytesReference payload, DiscoveryNode node) {
            this.action = action;
            this.payload = payload;
            this.node = node;
        }

        public RemoteProxyRequest(StreamInput in) throws IOException {
            super(in);
            this.action = in.readString();
            this.payload = in.readBytesReference();
            this.node = in.readOptionalWriteable(DiscoveryNode::new);
        }

        public String getAction() {
            return action;
        }

        public BytesReference getPayload() {
            return payload;
        }

        public DiscoveryNode getNode() {
            return node;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeString(action);
            out.writeBytesReference(payload);
            out.writeOptionalWriteable(node);
        }

        @Override
        public ActionRequestValidationException validate() {
            return null;
        }
    }

    public static class RemoteProxyResponse extends ActionResponse {

        private final BytesReference body;

        public RemoteProxyResponse(BytesReference body) {
            this.body = body;
        }

        public RemoteProxyResponse(StreamInput in) throws IOException {
            super(in);
            this.body = in.readBytesReference();
        }

        public BytesReference getBody() {
            return body;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeBytesReference(body);
        }
    }

    public static class TransportAction extends HandledTransportAction<RemoteProxyRequest, RemoteProxyResponse> {

        private final TransportService transportService;
        private final NodeClient nodeClient;

        @Inject
        public TransportAction(TransportService transportService, ActionFilters actionFilters, NodeClient nodeClient) {
            super(RemoteProxyAction.NAME, transportService, actionFilters, RemoteProxyRequest::new);
            this.transportService = transportService;
            this.nodeClient = nodeClient;
        }

        @Override
        protected void doExecute(Task task, RemoteProxyRequest request, ActionListener<RemoteProxyResponse> listener) {

            final RequestHandlerRegistry<? extends TransportRequest> requestHandler = transportService.getRequestHandler(
                request.getAction()
            );
            final TransportRequest transportRequest;
            try {
                transportRequest = requestHandler.newRequest(
                    new NamedWriteableAwareStreamInput(request.getPayload().streamInput(), nodeClient.getNamedWriteableRegistry())
                );
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }

            final Writeable.Reader<? extends ActionResponse> responseReader = nodeClient.getResponseReader(request.action);
            final ActionListenerResponseHandler<? extends TransportResponse> actionListenerResponseHandler =
                new ActionListenerResponseHandler<>(listener.map((actionResponse -> {
                    final BytesStreamOutput out = new BytesStreamOutput();
                    try {
                        actionResponse.writeTo(out);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                    return new RemoteProxyResponse(out.bytes());
                })), responseReader);

            logger.info("Requested node is [{}]", request.getNode());

            final ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
            try (var ignore = threadContext.stashContext()) {
                threadContext.markAsSystemContext();
                transportService.sendChildRequest(
                    request.getNode() != null ? request.getNode() : transportService.getLocalNode(),
                    request.getAction(),
                    transportRequest,
                    task,
                    TransportRequestOptions.EMPTY,
                    actionListenerResponseHandler
                );
            }
        }
    }
}
