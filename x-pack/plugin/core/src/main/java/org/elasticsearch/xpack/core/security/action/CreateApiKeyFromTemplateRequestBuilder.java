/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.action.ActionRequestBuilder;
import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.client.ElasticsearchClient;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.xpack.core.security.xcontent.XContentUtils;

import java.io.IOException;
import java.io.InputStream;

/**
 * Request builder for populating a {@link CreateApiKeyFromTemplateRequest}
 */
public final class CreateApiKeyFromTemplateRequestBuilder extends ActionRequestBuilder<CreateApiKeyFromTemplateRequest, CreateApiKeyFromTemplateResponse> {

    static ParseField NAME = new ParseField("name");

    public CreateApiKeyFromTemplateRequestBuilder(ElasticsearchClient client) {
        super(client, CreateApiKeyFromTemplateAction.INSTANCE, new CreateApiKeyFromTemplateRequest());
    }

    public CreateApiKeyFromTemplateRequestBuilder setTemplateId(String templateId) {
        request.setTemplateName(templateId);
        return this;
    }

    public CreateApiKeyFromTemplateRequestBuilder setName(String name) {
        request.setName(name);
        return this;
    }

    public CreateApiKeyFromTemplateRequestBuilder setRefreshPolicy(WriteRequest.RefreshPolicy refreshPolicy) {
        request.setRefreshPolicy(refreshPolicy);
        return this;
    }

    public CreateApiKeyFromTemplateRequestBuilder source(BytesReference source, XContentType xContentType) throws IOException {
        final NamedXContentRegistry registry = NamedXContentRegistry.EMPTY;
        try (InputStream stream = source.streamInput();
                XContentParser parser = xContentType.xContent().createParser(registry, LoggingDeprecationHandler.INSTANCE, stream)) {

            XContentUtils.verifyObject(parser);
            XContentParser.Token token;
            String currentFieldName = null;
            while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
                if (token == XContentParser.Token.FIELD_NAME) {
                    currentFieldName = parser.currentName();
                } else if (NAME.match(currentFieldName, parser.getDeprecationHandler())) {
                    if (token == XContentParser.Token.VALUE_STRING) {
                        setName(parser.text());
                    } else if (token != XContentParser.Token.VALUE_NULL) {
                        throw new ElasticsearchParseException(
                            "expected field [{}] to be of type string, but found [{}] instead", currentFieldName, token);
                    }
                } else {
                    throw new ElasticsearchParseException("failed to parse add user request. unexpected field [{}]", currentFieldName);
                }
            }
        }
        return this;
    }
}
