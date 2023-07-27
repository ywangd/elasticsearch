/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.rest.action.apikey;

import org.elasticsearch.client.internal.node.NodeClient;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.rest.Scope;
import org.elasticsearch.rest.ServerlessScope;
import org.elasticsearch.rest.action.RestBuilderListener;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xpack.core.security.action.apikey.GetApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.apikey.GetCrossClusterKeyAction;
import org.elasticsearch.xpack.core.security.action.apikey.GetCrossClusterKeyResponse;

import java.io.IOException;
import java.util.List;

import static org.elasticsearch.rest.RestRequest.Method.GET;

/**
 * Rest action to get one or more API keys information.
 */
@ServerlessScope(Scope.PUBLIC)
public final class RestGetCrossClusterKeyAction extends ApiKeyBaseRestHandler {

    public RestGetCrossClusterKeyAction(Settings settings, XPackLicenseState licenseState) {
        super(settings, licenseState);
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, "/_security/cross_cluster_key"), new Route(GET, "/_security/cross_cluster_key/{ids}"));
    }

    @Override
    protected RestChannelConsumer innerPrepareRequest(RestRequest request, NodeClient client) throws IOException {
        final String[] keyIds = request.paramAsStringArray("ids", Strings.EMPTY_ARRAY);
        // TODO support multiple IDs
        final String keyId = keyIds.length == 0 ? null : keyIds[0];

        final String keyName = request.param("name");
        final GetApiKeyRequest getApiKeyRequest = GetApiKeyRequest.builder()

            .apiKeyId(keyId)
            .apiKeyName(keyName)
            .build();
        return channel -> client.execute(GetCrossClusterKeyAction.INSTANCE, getApiKeyRequest, new RestBuilderListener<>(channel) {
            @Override
            public RestResponse buildResponse(GetCrossClusterKeyResponse getCrossClusterKeyResponse, XContentBuilder builder)
                throws Exception {
                getCrossClusterKeyResponse.toXContent(builder, channel.request());

                // return HTTP status 404 if no cross cluster key found for key id
                if (Strings.hasText(keyId) && getCrossClusterKeyResponse.getCrossClusterKeysInfo().length == 0) {
                    return new RestResponse(RestStatus.NOT_FOUND, builder);
                }
                return new RestResponse(RestStatus.OK, builder);
            }

        });
    }

    @Override
    public String getName() {
        return "xpack_security_get_cross_cluster_key";
    }

}
