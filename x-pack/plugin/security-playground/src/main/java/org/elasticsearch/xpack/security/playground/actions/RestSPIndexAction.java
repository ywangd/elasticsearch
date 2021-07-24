/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.actions;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.action.RestToXContentListener;

import java.io.IOException;
import java.util.List;

public class RestSPIndexAction extends SPBaseRestHandler {

    public RestSPIndexAction(Settings settings, XPackLicenseState licenseState) {
        super(settings, licenseState);
    }

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(RestRequest.Method.GET, "/_security_playground/index"),
            new Route(RestRequest.Method.GET, "/_security_playground/index/{index}")
        );
    }

    @Override
    public String getName() {
        return "xpack_security_playground_index_action";
    }

    @Override
    protected RestChannelConsumer innerPrepareRequest(RestRequest request, NodeClient client) throws IOException {
        request.param("verbose");  // consume it
        final String[] indices = Strings.splitStringByCommaToArray(request.param("index"));
        // TODO: define accessible index patterns
        return channel -> client.execute(SPIndexAction.INSTANCE, new SPIndexAction.Request(indices), new RestToXContentListener<>(channel));
    }
}
