/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.rest.action.apikey;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.rest.action.RestBuilderListener;
import org.elasticsearch.xpack.core.security.action.GetApiKeyTemplateAction;
import org.elasticsearch.xpack.core.security.action.GetApiKeyTemplateRequest;
import org.elasticsearch.xpack.core.security.action.GetApiKeyTemplateResponse;

import java.io.IOException;
import java.util.List;

import static org.elasticsearch.rest.RestRequest.Method.GET;

/**
 * Rest action to get one or more API keys information.
 */
public final class RestGetApiKeyTemplateAction extends ApiKeyBaseRestHandler {

    public RestGetApiKeyTemplateAction(Settings settings, XPackLicenseState licenseState) {
        super(settings, licenseState);
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, "/_security/api_key_template"));
    }

    @Override
    protected RestChannelConsumer innerPrepareRequest(RestRequest request, NodeClient client) throws IOException {
        final String templateName = request.param("name");
        final String userName = request.param("username");
        final String realmName = request.param("realm_name");
        final boolean myApiKeyTemplatesOnly = request.paramAsBoolean("owner", false);
        final GetApiKeyTemplateRequest getApiKeyTemplateRequest = new GetApiKeyTemplateRequest(realmName, userName, templateName, myApiKeyTemplatesOnly);
        return channel -> client.execute(GetApiKeyTemplateAction.INSTANCE, getApiKeyTemplateRequest,
                new RestBuilderListener<GetApiKeyTemplateResponse>(channel) {
                    @Override
                    public RestResponse buildResponse(GetApiKeyTemplateResponse getApiKeyTemplateResponse, XContentBuilder builder) throws Exception {
                        getApiKeyTemplateResponse.toXContent(builder, channel.request());

                        return new BytesRestResponse(RestStatus.OK, builder);
                    }

                });
    }

    @Override
    public String getName() {
        return "xpack_security_get_api_key_template";
    }

}
