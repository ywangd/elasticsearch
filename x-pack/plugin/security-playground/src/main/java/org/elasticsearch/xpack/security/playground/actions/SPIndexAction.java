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
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;

import java.io.IOException;

import static org.elasticsearch.action.search.SearchRequest.DEFAULT_INDICES_OPTIONS;

public class SPIndexAction extends ActionType<SPIndexAction.Response> {

    public static final String NAME = "indices:monitor/xpack/security/playground/index";
    public static final SPIndexAction INSTANCE = new SPIndexAction();

    public SPIndexAction() {
        super(NAME, Response::new);
    }

    public static class Request extends ActionRequest implements IndicesRequest.Replaceable {

        private String[] indices = Strings.EMPTY_ARRAY;
        private IndicesOptions indicesOptions = DEFAULT_INDICES_OPTIONS;

        public Request() {}

        public Request(String[] indices) {
            this.indices = indices;
        }

        public Request(StreamInput in) throws IOException {
            super(in);
            this.indices = in.readStringArray();
        }

        @Override
        public ActionRequestValidationException validate() {
            return null;
        }

        @Override
        public String[] indices() {
            return indices;
        }

        @Override
        public IndicesOptions indicesOptions() {
            return indicesOptions;
        }

        @Override
        public IndicesRequest indices(String... indices) {
            this.indices = indices;
            return this;
        }

        @Override
        public boolean includeDataStreams() {
            return true;
        }
    }

    public static class Response extends ActionResponse implements ToXContentObject {
        public String[] resolvedNames;

        public Response(String[] resolvedNames) {
            this.resolvedNames = resolvedNames;
        }

        public Response(StreamInput in) throws IOException {
            super(in);
            this.resolvedNames = in.readStringArray();
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject().field("count", resolvedNames.length);
            if (params.paramAsBoolean("verbose", false)) {
                builder.field("resolved_names", resolvedNames);
            }
            return builder.endObject();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeStringArray(resolvedNames);
        }
    }

}
