/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.action.ActionRequestBuilder;
import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.client.ElasticsearchClient;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import static org.elasticsearch.common.xcontent.ConstructingObjectParser.constructorArg;
import static org.elasticsearch.common.xcontent.ConstructingObjectParser.optionalConstructorArg;

/**
 * Request builder for populating a {@link CreateApiKeyTemplateRequest}
 */
public final class CreateApiKeyTemplateRequestBuilder extends ActionRequestBuilder<CreateApiKeyTemplateRequest, CreateApiKeyTemplateResponse> {

    @SuppressWarnings("unchecked")
    static final ConstructingObjectParser<CreateApiKeyTemplateRequest, Void> PARSER = new ConstructingObjectParser<>(
            "api_key_template_request", false, (args, v) -> {
                return new CreateApiKeyTemplateRequest((String) args[0], (List<RoleDescriptor>) args[1],
                        TimeValue.parseTimeValue((String) args[2], null, "expiration"),
                        TimeValue.parseTimeValue((String) args[2], null, "keExpiration"));
            });

    static {
        PARSER.declareString(constructorArg(), new ParseField("name"));
        PARSER.declareNamedObjects(optionalConstructorArg(), (p, c, n) -> {
            p.nextToken();
            return RoleDescriptor.parse(n, p, false);
        }, new ParseField("role_descriptors"));
        PARSER.declareString(optionalConstructorArg(), new ParseField("expiration"));
        PARSER.declareString(optionalConstructorArg(), new ParseField("keyExpiration"));
    }

    public CreateApiKeyTemplateRequestBuilder(ElasticsearchClient client) {
        super(client, CreateApiKeyTemplateAction.INSTANCE, new CreateApiKeyTemplateRequest());
    }

    public CreateApiKeyTemplateRequestBuilder setName(String name) {
        request.setName(name);
        return this;
    }

    public CreateApiKeyTemplateRequestBuilder setExpiration(TimeValue expiration) {
        request.setExpiration(expiration);
        return this;
    }

    public CreateApiKeyTemplateRequestBuilder setKeyExpiration(TimeValue keyExpiration) {
        request.setKeyExpiration(keyExpiration);
        return this;
    }

    public CreateApiKeyTemplateRequestBuilder setRoleDescriptors(List<RoleDescriptor> roleDescriptors) {
        request.setRoleDescriptors(roleDescriptors);
        return this;
    }

    public CreateApiKeyTemplateRequestBuilder setRefreshPolicy(WriteRequest.RefreshPolicy refreshPolicy) {
        request.setRefreshPolicy(refreshPolicy);
        return this;
    }

    public CreateApiKeyTemplateRequestBuilder source(BytesReference source, XContentType xContentType) throws IOException {
        final NamedXContentRegistry registry = NamedXContentRegistry.EMPTY;
        try (InputStream stream = source.streamInput();
                XContentParser parser = xContentType.xContent().createParser(registry, LoggingDeprecationHandler.INSTANCE, stream)) {
            CreateApiKeyTemplateRequest createApiKeyTemplateRequest = parse(parser);
            setName(createApiKeyTemplateRequest.getName());
            setRoleDescriptors(createApiKeyTemplateRequest.getRoleDescriptors());
            setExpiration(createApiKeyTemplateRequest.getExpiration());
            setKeyExpiration(createApiKeyTemplateRequest.getKeyExpiration());
        }
        return this;
    }

    public static CreateApiKeyTemplateRequest parse(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }
}
