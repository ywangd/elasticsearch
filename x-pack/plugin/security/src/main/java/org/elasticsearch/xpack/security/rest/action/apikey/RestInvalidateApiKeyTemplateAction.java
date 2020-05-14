/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.rest.action.apikey;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.rest.action.RestBuilderListener;
import org.elasticsearch.xpack.core.security.action.InvalidateApiKeyTemplateAction;
import org.elasticsearch.xpack.core.security.action.InvalidateApiKeyTemplateRequest;
import org.elasticsearch.xpack.core.security.action.InvalidateApiKeyTemplateResponse;

import java.io.IOException;
import java.util.List;

import static org.elasticsearch.rest.RestRequest.Method.DELETE;

/**
 * Rest action to invalidate one or more API keys
 */
public final class RestInvalidateApiKeyTemplateAction extends ApiKeyBaseRestHandler {
    static final ConstructingObjectParser<InvalidateApiKeyTemplateRequest, Void> PARSER = new ConstructingObjectParser<>("invalidate_api_key_template",
            a -> {
                return new InvalidateApiKeyTemplateRequest((String) a[0], (String) a[1], (String) a[2], (a[3] == null) ? false :
                    (Boolean) a[3]);
            });

    static {
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), new ParseField("realm_name"));
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), new ParseField("username"));
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), new ParseField("name"));
        PARSER.declareBoolean(ConstructingObjectParser.optionalConstructorArg(), new ParseField("owner"));
    }

    public RestInvalidateApiKeyTemplateAction(Settings settings, XPackLicenseState licenseState) {
        super(settings, licenseState);
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(DELETE, "/_security/api_key_template"));
    }

    @Override
    protected RestChannelConsumer innerPrepareRequest(RestRequest request, NodeClient client) throws IOException {
        try (XContentParser parser = request.contentParser()) {
            final InvalidateApiKeyTemplateRequest invalidateApiKeyTemplateRequest = PARSER.parse(parser, null);
            return channel -> client.execute(InvalidateApiKeyTemplateAction.INSTANCE, invalidateApiKeyTemplateRequest,
                new RestBuilderListener<InvalidateApiKeyTemplateResponse>(channel) {
                    @Override
                    public RestResponse buildResponse(InvalidateApiKeyTemplateResponse invalidateResp,
                                                      XContentBuilder builder) throws Exception {
                        invalidateResp.toXContent(builder, channel.request());
                        return new BytesRestResponse(RestStatus.OK, builder);
                    }
                });
        }
    }

    @Override
    public String getName() {
        return "xpack_security_invalidate_api_key_template";
    }

}
