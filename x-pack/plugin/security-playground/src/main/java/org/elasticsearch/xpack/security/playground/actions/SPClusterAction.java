/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.actions;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.ActionType;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;

import java.io.IOException;

public class SPClusterAction extends ActionType<SPClusterAction.Response> {

    public static final String NAME = "cluster:admin/xpack/security/playground/cluster";
    public static final SPClusterAction INSTANCE = new SPClusterAction();

    public SPClusterAction() {
        super(NAME, in -> Response.INSTANCE);
    }

    public static class Request extends ActionRequest {
        public static final Request INSTANCE = new Request();

        @Override
        public ActionRequestValidationException validate() {
            return null;
        }
    }

    public static class Response extends ActionResponse implements ToXContentObject {
        public static final Response INSTANCE = new Response();

        public Response() {}

        public Response(StreamInput in) throws IOException {
            super(in);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            return builder.startObject().endObject();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {}
    }

}
