/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.rest.action.apikey;

import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.action.RestToXContentListener;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyTemplateRequest;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyTemplateRequestBuilder;

import java.io.IOException;
import java.util.List;

import static org.elasticsearch.rest.RestRequest.Method.POST;
import static org.elasticsearch.rest.RestRequest.Method.PUT;

/**
 * Rest action to create an API key
 */
public final class RestCreateApiKeyTemplateAction extends ApiKeyBaseRestHandler {

    /**
     * @param settings the node's settings
     * @param licenseState the license state that will be used to determine if
     * security is licensed
     */
    public RestCreateApiKeyTemplateAction(Settings settings, XPackLicenseState licenseState) {
        super(settings, licenseState);
    }

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(POST, "/_security/api_key_template"));
    }

    @Override
    public String getName() {
        return "xpack_security_create_api_key_template";
    }

    @Override
    protected RestChannelConsumer innerPrepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        String refresh = request.param("refresh");
        CreateApiKeyTemplateRequestBuilder builder = new CreateApiKeyTemplateRequestBuilder(client)
            .source(request.requiredContent(), request.getXContentType())
            .setRefreshPolicy((refresh != null) ?
                WriteRequest.RefreshPolicy.parse(request.param("refresh")) : CreateApiKeyTemplateRequest.DEFAULT_REFRESH_POLICY);
        return channel -> builder.execute(new RestToXContentListener<>(channel));
    }
}
