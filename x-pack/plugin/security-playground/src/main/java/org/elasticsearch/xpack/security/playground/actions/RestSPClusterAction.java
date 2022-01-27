/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.actions;

import org.elasticsearch.client.internal.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.action.RestToXContentListener;

import java.io.IOException;
import java.util.List;

public class RestSPClusterAction extends SPBaseRestHandler {

    public RestSPClusterAction(Settings settings, XPackLicenseState licenseState) {
        super(settings, licenseState);
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.GET, "/_security_playground/cluster"));
    }

    @Override
    public String getName() {
        return "xpack_security_playground_cluster_action";
    }

    @Override
    protected RestChannelConsumer innerPrepareRequest(RestRequest request, NodeClient client) throws IOException {
        return channel -> client.execute(SPClusterAction.INSTANCE, SPClusterAction.Request.INSTANCE, new RestToXContentListener<>(channel));
    }
}
