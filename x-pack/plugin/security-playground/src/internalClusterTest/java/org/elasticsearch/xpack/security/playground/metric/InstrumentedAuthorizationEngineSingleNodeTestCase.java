/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.metric;

import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.Response;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.test.SecurityPlaygroundSingleNodeTestCase;
import org.elasticsearch.xpack.security.playground.actions.GetMetricHistogramAction;
import org.elasticsearch.xpack.security.playground.actions.SPIndexAction;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.elasticsearch.xcontent.json.JsonXContent.jsonXContent;
import static org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken.basicAuthHeaderValue;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class InstrumentedAuthorizationEngineSingleNodeTestCase extends SecurityPlaygroundSingleNodeTestCase {

    @Override
    protected Settings nodeSettings() {
        return Settings.builder()
            .put(super.nodeSettings())
            // Need 2 threads because the proxy API fires a second request while handling the first request
            .put(EsExecutors.NODE_PROCESSORS_SETTING.getKey(), 2)
            .build();
    }

    public void testSPIndexTransport() {
        final String xOpaqueId = randomAlphaOfLength(20);
        try (ThreadContext.StoredContext ignored = client().threadPool().getThreadContext().newStoredContext(false)) {
            client().threadPool().getThreadContext().putHeader(Task.X_OPAQUE_ID, xOpaqueId);
            client().threadPool().getThreadContext().putHeader(Task.TRACE_ID, randomAlphaOfLength(32));
            final SPIndexAction.Response response = client().execute(SPIndexAction.INSTANCE, new SPIndexAction.Request()).actionGet();
            assertNotNull(response.resolvedNames);
        }
    }

    public void testSPIndexRest() throws IOException {
        final Request request = newRequest("GET", "/_security_playground/index");
        assertOK(getRestClient().performRequest(request));
    }

    public void testMetricProxy() throws IOException {
        final Request request = newRequest("POST", "/_security_playground/metric/proxy");
        request.setJsonEntity("{\"path\":\"/_security_playground/index\"}");
        final Map<String, Object> m = responseAsMap(getRestClient().performRequest(request));
        final Map<String, Object> _metric = getFieldAsMap(m, "_metric");
        assertThat(_metric.get("cluster_name"), notNullValue());
        assertThat(_metric.get("master_node_name"), notNullValue());
        assertThat(_metric.get("node_name"), notNullValue());
        final Map<String, Object> _nodes = getFieldAsMap(_metric, "_nodes");
        assertThat(_nodes.get("total"), equalTo(1));
        assertThat(_nodes.get("successful"), equalTo(1));

        final Map<String, Object> nodes = getFieldAsMap(_metric, "nodes");
        assertThat(nodes.size(), equalTo(1));
        final Map<String, Object> node = getFieldAsMap(nodes, nodes.keySet().stream().findFirst().orElseThrow());
        assertThat(node.get("id"), notNullValue());
        assertThat(node.get("x_opaque_id"), notNullValue());
        final List<Map<String, Object>> requests = getFieldAsListOfMap(node, "requests");
        assertThat(requests.size(), equalTo(1));
        final Map<String, Object> r = requests.get(0);
        assertThat(r.get("action"), equalTo("indices:monitor/xpack/security/playground/index"));
        assertThat(r.get("request_hash"), notNullValue());
        assertThat(r.get("start_time"), notNullValue());
        assertThat((int) r.get("index"), equalTo(0));
        final Map<String, Object> metric = getFieldAsMap(r, "metric");
        assertThat((int) metric.get("resolve_authorization_info"), greaterThan(0));
        assertThat(metric.get("authorize_run_as"), nullValue());
        assertThat(metric.get("authorize_cluster_action"), nullValue());
        assertThat((int) metric.get("authorize_index_action"), greaterThan(0));
        assertThat((int) metric.get("load_authorized_indices"), greaterThan(0));
    }

    public void testMetricHistogram() throws IOException, InterruptedException {
        try (ThreadContext.StoredContext ignored = client().threadPool().getThreadContext().newStoredContext(false)) {
            client().threadPool().getThreadContext().putHeader(Task.X_OPAQUE_ID, "search");
            client().search(new SearchRequest()).actionGet();
        }
        try (ThreadContext.StoredContext ignored = client().threadPool().getThreadContext().newStoredContext(false)) {
            client().threadPool().getThreadContext().putHeader(Task.X_OPAQUE_ID, "health");
            client().admin().cluster().health(new ClusterHealthRequest()).actionGet();
        }

        Thread.sleep(500);

        final GetMetricHistogramAction.Response response1 = client().execute(
            GetMetricHistogramAction.INSTANCE,
            new GetMetricHistogramAction.Request()
        ).actionGet();
        assertNull(response1.getXOpaqueId());
        assertThat(response1.getLocalNodeName(), equalTo(response1.getMasterNodeName()));
        assertThat(response1.failures(), empty());
        assertThat(response1.getNodes().size(), equalTo(1));
        final GetMetricHistogramAction.NodeResponse nodeResponse1 = response1.getNodes().get(0);
        assertThat(nodeResponse1.getHistograms().size(), equalTo(12));
        assertThat(
            nodeResponse1.getHistograms()
                .stream()
                .filter(histogramMetric -> histogramMetric.method == InstrumentedMethod.RESOLVE_AUTHORIZATION_INFO)
                .findFirst()
                .orElseThrow().count,
            greaterThanOrEqualTo(2L)
        );
        assertThat(
            nodeResponse1.getHistograms()
                .stream()
                .filter(histogramMetric -> histogramMetric.method == InstrumentedMethod.AUTHORIZE_RUN_AS)
                .findFirst()
                .orElseThrow().count,
            equalTo(0L)
        );
        assertThat(
            nodeResponse1.getHistograms()
                .stream()
                .filter(histogramMetric -> histogramMetric.method == InstrumentedMethod.AUTHORIZE_CLUSTER_ACTION)
                .findFirst()
                .orElseThrow().count,
            greaterThanOrEqualTo(1L)
        );
        assertThat(
            nodeResponse1.getHistograms()
                .stream()
                .filter(histogramMetric -> histogramMetric.method == InstrumentedMethod.AUTHORIZE_INDEX_ACTION)
                .findFirst()
                .orElseThrow().count,
            greaterThanOrEqualTo(1L)
        );

        final GetMetricHistogramAction.Response response2 = client().execute(
            GetMetricHistogramAction.INSTANCE,
            new GetMetricHistogramAction.Request("search")
        ).actionGet();
        assertThat(response2.getXOpaqueId(), equalTo("search"));
        assertThat(response2.failures(), empty());
        final GetMetricHistogramAction.NodeResponse nodeResponse2 = response2.getNodes().get(0);
        assertThat(
            nodeResponse2.getHistograms()
                .stream()
                .filter(histogramMetric -> histogramMetric.method == InstrumentedMethod.RESOLVE_AUTHORIZATION_INFO)
                .findFirst()
                .orElseThrow().count,
            equalTo(1L)
        );
        assertThat(
            nodeResponse2.getHistograms()
                .stream()
                .filter(histogramMetric -> histogramMetric.method == InstrumentedMethod.AUTHORIZE_CLUSTER_ACTION)
                .findFirst()
                .orElseThrow().count,
            equalTo(0L)
        );
        assertThat(
            nodeResponse2.getHistograms()
                .stream()
                .filter(histogramMetric -> histogramMetric.method == InstrumentedMethod.AUTHORIZE_INDEX_ACTION)
                .findFirst()
                .orElseThrow().count,
            equalTo(1L)
        );

        final GetMetricHistogramAction.Response response3 = client().execute(
            GetMetricHistogramAction.INSTANCE,
            new GetMetricHistogramAction.Request("health")
        ).actionGet();
        assertThat(response3.getXOpaqueId(), equalTo("health"));
        assertThat(response3.failures(), empty());
        final GetMetricHistogramAction.NodeResponse nodeResponse3 = response3.getNodes().get(0);
        assertThat(
            nodeResponse3.getHistograms()
                .stream()
                .filter(histogramMetric -> histogramMetric.method == InstrumentedMethod.RESOLVE_AUTHORIZATION_INFO)
                .findFirst()
                .orElseThrow().count,
            equalTo(1L)
        );
        assertThat(
            nodeResponse3.getHistograms()
                .stream()
                .filter(histogramMetric -> histogramMetric.method == InstrumentedMethod.AUTHORIZE_CLUSTER_ACTION)
                .findFirst()
                .orElseThrow().count,
            equalTo(1L)
        );
        assertThat(
            nodeResponse3.getHistograms()
                .stream()
                .filter(histogramMetric -> histogramMetric.method == InstrumentedMethod.AUTHORIZE_INDEX_ACTION)
                .findFirst()
                .orElseThrow().count,
            equalTo(0L)
        );
    }

    private Request newRequest(String method, String path) {
        final Request request = new Request(method, path);
        request.setOptions(
            request.getOptions().toBuilder().addHeader("Authorization", basicAuthHeaderValue(nodeClientUsername(), nodeClientPassword()))
        );
        return request;
    }

    private Request addXOpaqueId(Request request, String xOpaqueId) {
        request.setOptions(request.getOptions().toBuilder().addHeader(Task.X_OPAQUE_ID, xOpaqueId));
        return request;
    }

    private Map<String, Object> responseAsMap(Response response) throws IOException {
        assertOK(response);
        return XContentHelper.convertToMap(jsonXContent, response.getEntity().getContent(), true);
    }

    private void assertOK(Response response) {
        assertThat(response.getStatusLine().getStatusCode(), equalTo(200));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getFieldAsMap(Map<String, Object> m, String fieldName) {
        return (Map<String, Object>) m.get(fieldName);
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> getFieldAsListOfMap(Map<String, Object> m, String fieldName) {
        return (List<Map<String, Object>>) m.get(fieldName);
    }
}
