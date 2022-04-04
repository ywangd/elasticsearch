/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground;

import org.elasticsearch.client.Request;
import org.elasticsearch.client.Response;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.test.rest.ESRestTestCase;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.util.Map;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;

public class SecurityPlaygroundPluginIT extends ESRestTestCase {

    @Before
    public void setUpTraceLogging() throws IOException {
        final Request request = new Request("PUT", "/_cluster/settings");
        request.setJsonEntity(
            "{\"transient\":" + "{\"logger.org.elasticsearch.xpack.security.playground.authz.InstrumentedAuthorizationEngine\":\"TRACE\"}}"
        );
        assertOK(adminClient().performRequest(request));
    }

    @After
    public void tearDownTraceLogging() throws IOException {
        final Request request = new Request("PUT", "/_cluster/settings");
        request.setJsonEntity(
            "{\"transient\":" + "{\"logger.org.elasticsearch.xpack.security.playground.authz.InstrumentedAuthorizationEngine\":null}}"
        );
        assertOK(adminClient().performRequest(request));
    }

    @Override
    protected Settings restAdminSettings() {
        String token = basicAuthHeaderValue("test_admin", new SecureString("x-pack-test-password".toCharArray()));
        return Settings.builder().put(ThreadContext.PREFIX + ".Authorization", token).build();
    }

    public void testClusterWorks() throws IOException {
        final Request request = new Request("GET", "/_cluster/health");
        final Response response = adminClient().performRequest(request);
        assertOK(response);
        assertThat(responseAsMap(response).get("number_of_nodes"), equalTo(2));
    }

    public void testSPIndex() throws IOException {
        final Request request = new Request("GET", "/_security_playground/index");
        final Response response = adminClient().performRequest(request);
        assertOK(response);
    }

    // TODO: this fails because Transports.assertDefaultThreadContext does not allow TRACE_ID
    public void testMetricProxySimple() throws IOException {
        final Request request = new Request("POST", "/_security_playground/metric/proxy");
        request.setJsonEntity("{\"method\":\"GET\",\"path\":\"/\"}");
        final Response response = adminClient().performRequest(request);
        assertOK(response);
        final Map<String, Object> responseMap = responseAsMap(response);
        assertNotNull(responseMap.get("_metric"));
        assertNotNull(responseMap.get("cluster_name"));
        assertNotNull(responseMap.get("version"));
    }

    public void testMetricProxyIndex() throws IOException {
        final Request indexRequest = new Request("PUT", "/index/_doc/1?refresh=wait_for");
        indexRequest.setJsonEntity("{\"foo\": \"bar\"}");
        assertOK(adminClient().performRequest(indexRequest));

        final Request request = new Request("POST", "/_security_playground/metric/proxy");
        request.setJsonEntity("{\"method\":\"GET\",\"path\":\"/_search\",\"body\":{\"query\":{\"match_all\":{}}}}");
        final Response response = adminClient().performRequest(request);
        assertOK(response);
        final Map<String, Object> responseMap = responseAsMap(response);
        assertNotNull(responseMap.get("_metric"));
        assertNotNull(responseMap.get("hits"));
    }

    public void testMetricHistogram() throws IOException, InterruptedException {
        final String xOpaqueId = randomAlphaOfLength(20);
        final Request request2 = new Request("POST", "/_security/role/*/_clear_cache");
        request2.setOptions(request2.getOptions().toBuilder().addHeader(Task.X_OPAQUE_ID_HTTP_HEADER, xOpaqueId));
        final Response response = adminClient().performRequest(request2);
        assertOK(response);

        Thread.sleep(1000);

        final Metrics metrics = extractMetricsFromHistogram(xOpaqueId);
        assertNotNull(metrics.local);
        assertNotNull(metrics.remote);
        assertNull(metrics.local.authorizeRunAs);
        assertNull(metrics.local.authorizeIndexAction);
        assertNull(metrics.local.loadAuthorizedIndices);
        assertNull(metrics.remote.authorizeRunAs);
        assertNull(metrics.remote.authorizeIndexAction);
        assertNull(metrics.remote.loadAuthorizedIndices);

        assertThat(metrics.local.resolveAuthorizationInfo.get("count"), greaterThan(0));
        assertThat(metrics.local.authorizeClusterAction.get("count"), greaterThan(0));

        // metric should be rest by previous call
        assertAllZeroMetrics(extractMetricsFromHistogram(xOpaqueId));
    }

    public void testAuthorizationMetricsHistogramRequiresXOpaqueId() throws IOException {
        // reset metric
        extractMetricsFromHistogram();
        assertAllZeroMetrics(extractMetricsFromHistogram());
        final Request request1 = new Request("PUT", "/index2");
        assertOK(adminClient().performRequest(request1));
        assertAllZeroMetrics(extractMetricsFromHistogram());
    }

    private Metrics extractMetricsFromHistogram() throws IOException {
        return extractMetricsFromHistogram(null);
    }

    @SuppressWarnings("unchecked")
    private Metrics extractMetricsFromHistogram(String xOpaqueId) throws IOException {
        final Request histogramRequest = new Request("GET", "/_security_playground/metric/histogram");
        if (xOpaqueId != null) {
            histogramRequest.addParameter("x_opaque_id", xOpaqueId);
        }
        final Response histogramResponse = adminClient().performRequest(histogramRequest);
        assertOK(histogramResponse);
        final Map<String, Object> m = responseAsMap(histogramResponse);
        final String masterNodeName = (String) m.get("master_node_name");
        final String localNodeName = (String) m.get("node_name");
        final Metrics metrics = new Metrics(localNodeName.equals(masterNodeName));
        final Map<String, Object> _nodes = (Map<String, Object>) m.get("_nodes");
        assertNotNull(_nodes);
        assertThat(_nodes.get("total"), equalTo(2));
        assertThat(_nodes.get("successful"), equalTo(2));
        final Map<String, Object> nodes = (Map<String, Object>) m.get("nodes");
        for (Map.Entry<String, Object> entry : nodes.entrySet()) {
            final Map<String, Object> value = (Map<String, Object>) entry.getValue();
            final Map<String, Object> metricMap = (Map<String, Object>) value.get("metric");
            final Metric metric;
            if (metricMap.isEmpty()) {
                metric = null;
            } else {
                metric = new Metric(
                    (Map<String, Integer>) metricMap.get("resolve_authorization_info"),
                    (Map<String, Integer>) metricMap.get("authorize_run_as"),
                    (Map<String, Integer>) metricMap.get("authorize_cluster_action"),
                    (Map<String, Integer>) metricMap.get("authorize_index_action"),
                    (Map<String, Integer>) metricMap.get("load_authorized_indices")
                );
            }
            if (localNodeName.equals(entry.getKey())) {
                metrics.local = metric;
            } else {
                metrics.remote = metric;
            }
        }
        return metrics;
    }

    private void assertAllZeroMetrics(Metrics metrics) {
        assertNull(metrics.local);
        assertNull(metrics.remote);
    }

    private static class Metrics {
        boolean localIsMaster;
        Metric local;
        Metric remote;

        Metrics(boolean localIsMaster) {
            this.localIsMaster = localIsMaster;
        }
    }

    private static class Metric {
        final Map<String, Integer> resolveAuthorizationInfo;
        final Map<String, Integer> authorizeRunAs;
        final Map<String, Integer> authorizeClusterAction;
        final Map<String, Integer> authorizeIndexAction;
        final Map<String, Integer> loadAuthorizedIndices;

        private Metric(
            Map<String, Integer> resolveAuthorizationInfo,
            Map<String, Integer> authorizeRunAs,
            Map<String, Integer> authorizeClusterAction,
            Map<String, Integer> authorizeIndexAction,
            Map<String, Integer> loadAuthorizedIndices
        ) {
            this.resolveAuthorizationInfo = resolveAuthorizationInfo;
            this.authorizeRunAs = authorizeRunAs;
            this.authorizeClusterAction = authorizeClusterAction;
            this.authorizeIndexAction = authorizeIndexAction;
            this.loadAuthorizedIndices = loadAuthorizedIndices;
        }
    }
}
