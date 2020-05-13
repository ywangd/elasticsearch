/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static org.elasticsearch.common.xcontent.ConstructingObjectParser.optionalConstructorArg;

/**
 * Response for get API keys.<br>
 * The result contains information about the API keys that were found.
 */
public final class GetApiKeyTemplateResponse extends ActionResponse implements ToXContentObject, Writeable {

    private final ApiKeyTemplate[] foundApiKeyTemplatesInfo;

    public GetApiKeyTemplateResponse(StreamInput in) throws IOException {
        super(in);
        this.foundApiKeyTemplatesInfo = in.readArray(ApiKeyTemplate::new, ApiKeyTemplate[]::new);
    }

    public GetApiKeyTemplateResponse(Collection<ApiKeyTemplate> foundApiKeyTemplatesInfo) {
        Objects.requireNonNull(foundApiKeyTemplatesInfo, "found_api_keys_info must be provided");
        this.foundApiKeyTemplatesInfo = foundApiKeyTemplatesInfo.toArray(new ApiKeyTemplate[0]);
    }

    public static GetApiKeyTemplateResponse emptyResponse() {
        return new GetApiKeyTemplateResponse(Collections.emptyList());
    }

    public ApiKeyTemplate[] getApiKeyTemplateInfos() {
        return foundApiKeyTemplatesInfo;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
            .array("api_key_templates", (Object[]) foundApiKeyTemplatesInfo);
        return builder.endObject();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeArray(foundApiKeyTemplatesInfo);
    }

    @SuppressWarnings("unchecked")
    static final ConstructingObjectParser<GetApiKeyTemplateResponse, Void> PARSER = new ConstructingObjectParser<>("get_api_key_response", args -> {
        return (args[0] == null) ? GetApiKeyTemplateResponse.emptyResponse() : new GetApiKeyTemplateResponse((List<ApiKeyTemplate>) args[0]);
    });
    static {
        PARSER.declareObjectArray(optionalConstructorArg(), (p, c) -> ApiKeyTemplate.fromXContent(p), new ParseField("api_keys"));
    }

    public static GetApiKeyTemplateResponse fromXContent(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }

    @Override
    public String toString() {
        return "GetApiKeyTemplateResponse [foundApiKeyTemplatesInfo=" + foundApiKeyTemplatesInfo + "]";
    }

}
