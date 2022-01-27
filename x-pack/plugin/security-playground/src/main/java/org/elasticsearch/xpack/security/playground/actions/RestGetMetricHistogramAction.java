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
import org.elasticsearch.rest.action.RestActions;
import org.elasticsearch.xpack.security.rest.action.SecurityBaseRestHandler;

import java.io.IOException;
import java.util.List;

public class RestGetMetricHistogramAction extends SecurityBaseRestHandler {

    public RestGetMetricHistogramAction(Settings settings, XPackLicenseState licenseState) {
        super(settings, licenseState);
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.GET, "/_security_playground/metric/histogram"));
    }

    @Override
    public String getName() {
        return "xpack_security_playground_metric_histogram_action";
    }

    @Override
    protected RestChannelConsumer innerPrepareRequest(RestRequest request, NodeClient client) throws IOException {
        final String xOpaqueId = request.param("x_opaque_id");
        return channel -> client.execute(
            GetMetricHistogramAction.INSTANCE,
            new GetMetricHistogramAction.Request(xOpaqueId),
            new RestActions.NodesResponseRestListener<>(channel)
        );
    }
}
