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
import org.elasticsearch.xpack.core.security.action.SyncApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.SyncApiKeyRequestBuilder;

import java.io.IOException;
import java.util.List;

import static org.elasticsearch.rest.RestRequest.Method.POST;
import static org.elasticsearch.rest.RestRequest.Method.PUT;

/**
 * Rest action to create an API key
 */
public final class RestSyncApiKeyAction extends ApiKeyBaseRestHandler {

    /**
     * @param settings the node's settings
     * @param licenseState the license state that will be used to determine if
     * security is licensed
     */
    public RestSyncApiKeyAction(Settings settings, XPackLicenseState licenseState) {
        super(settings, licenseState);
    }

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(POST, "/_security/api_key/_sync"),
            new Route(PUT, "/_security/api_key/_sync"));
    }

    @Override
    public String getName() {
        return "xpack_security_sync_api_key";
    }

    @Override
    protected RestChannelConsumer innerPrepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        String refresh = request.param("refresh");
        SyncApiKeyRequestBuilder builder = new SyncApiKeyRequestBuilder(client)
            .setRefreshPolicy((refresh != null) ?
                WriteRequest.RefreshPolicy.parse(request.param("refresh")) : SyncApiKeyRequest.DEFAULT_REFRESH_POLICY);
        return channel -> builder.execute(new RestToXContentListener<>(channel));
    }
}
