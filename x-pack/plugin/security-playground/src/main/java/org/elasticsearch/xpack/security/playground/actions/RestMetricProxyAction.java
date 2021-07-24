/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.actions;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.ResponseException;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.UUIDs;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.InstantiatingObjectParser;
import org.elasticsearch.common.xcontent.ObjectParserHelper;
import org.elasticsearch.common.xcontent.ParseField;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.rest.action.RestBuilderListener;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.xpack.security.playground.RestClientComponent;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.elasticsearch.common.xcontent.ConstructingObjectParser.constructorArg;
import static org.elasticsearch.common.xcontent.ConstructingObjectParser.optionalConstructorArg;
import static org.elasticsearch.xpack.core.ClientHelper.SECURITY_ORIGIN;
import static org.elasticsearch.xpack.core.ClientHelper.executeAsyncWithOrigin;

public class RestMetricProxyAction extends SPBaseRestHandler {

    private static final Logger logger = LogManager.getLogger(RestMetricProxyAction.class);

    private static final Set<String> IGNORED_REQUEST_HEADERS = Set.of("content-length", "accept", "content-type", "x-opaque-id");

    private final RestClientComponent restClientComponent;

    public RestMetricProxyAction(Settings settings, XPackLicenseState licenseState, RestClientComponent restClientComponent) {
        super(settings, licenseState);
        this.restClientComponent = restClientComponent;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.POST, "/_security_playground/metric/proxy"));
    }

    @Override
    public String getName() {
        return "xpack_security_playground_metric_proxy_action";
    }

    @Override
    protected RestChannelConsumer innerPrepareRequest(RestRequest restRequest, NodeClient client) throws IOException {
        final String xOpaqueId = UUIDs.base64UUID();
        final Request clientRequest = convertToClientRequest(restRequest, xOpaqueId, generateTraceParent());
        final AtomicReference<Response> clientResponse = new AtomicReference<>();
        try {
            clientResponse.set(restClientComponent.performRequest(clientRequest));
        } catch (ResponseException e) {
            clientResponse.set(e.getResponse());
        }

        return channel -> executeAsyncWithOrigin(
            client,
            SECURITY_ORIGIN,
            GetMetricInstantAction.INSTANCE,
            new GetMetricInstantAction.Request(xOpaqueId),
            new RestBuilderListener<GetMetricInstantAction.Response>(channel) {
                @Override
                public RestResponse buildResponse(GetMetricInstantAction.Response response, XContentBuilder builder) throws Exception {
                    return convertToRestResponse(restRequest, clientResponse.get(), response, builder);
                }
            }
        );
    }

    private Request convertToClientRequest(RestRequest restRequest, String xOpaqueId, String traceparent) throws IOException {
        if (XContentType.JSON != restRequest.getXContentType()) {
            throw new IllegalArgumentException(
                "invalid xcontent type, this API only supports JSON, got [{" + restRequest.getXContentType() + "}]"
            );
        }
        final MetricProxyRequest proxyRequest = MetricProxyRequest.from(restRequest);
        final Request clientRequest = new Request(proxyRequest.method, proxyRequest.path);
        final RequestOptions.Builder requestOptionsBuilder = clientRequest.getOptions().toBuilder();
        restRequest.getHeaders().forEach((key, value) -> {
            if (false == IGNORED_REQUEST_HEADERS.contains(key.toLowerCase(Locale.ROOT))) {
                value.forEach(v -> requestOptionsBuilder.addHeader(key, v));
            }
        });
        requestOptionsBuilder.addHeader(Task.X_OPAQUE_ID, xOpaqueId).addHeader(Task.TRACE_PARENT, traceparent);
        clientRequest.setOptions(requestOptionsBuilder);
        if (proxyRequest.body != null) {
            String bodyString = proxyRequest.body.utf8ToString();
            // Body can either JSON or a string (for bulk request)
            if (bodyString.startsWith("\"")) {
                assert bodyString.length() > 1 && bodyString.endsWith("\"");
                bodyString = bodyString.substring(1, bodyString.length() - 1);
            }
            clientRequest.setJsonEntity(bodyString);
        }
        return clientRequest;
    }

    private RestResponse convertToRestResponse(
        RestRequest restRequest,
        Response clientResponse,
        GetMetricInstantAction.Response response,
        XContentBuilder builder
    ) throws IOException {
        final RestStatus restStatus = RestStatus.fromCode(clientResponse.getStatusLine().getStatusCode());
        final byte[] bytes = clientResponse.getEntity().getContent().readAllBytes();
        final String originalResponseBody = new String(bytes, StandardCharsets.UTF_8).trim();
        // TODO: better way for injecting metric data instead of string concat??
        final StringBuilder sb = new StringBuilder(
            originalResponseBody.length() == 0 ? "{" : originalResponseBody.substring(0, originalResponseBody.length() - 1)
        );
        if (originalResponseBody.length() > 2) {
            sb.append(",");
        }
        sb.append("\"_metric\":");
        // TODO: option to filter out internal users
        response.toXContent(builder, restRequest);
        sb.append(Strings.toString(builder));
        sb.append("}\n");
        final BytesRestResponse bytesRestResponse = new BytesRestResponse(restStatus, "application/json", sb.toString());
        Stream.of(clientResponse.getHeaders()).forEach(header -> {
            if (false == "content-length".equals(header.getName().toLowerCase(Locale.ROOT))) {
                bytesRestResponse.addHeader(header.getName(), header.getValue());
            }
        });
        return bytesRestResponse;
    }

    static final InstantiatingObjectParser<MetricProxyRequest, Void> PARSER;

    static {
        InstantiatingObjectParser.Builder<MetricProxyRequest, Void> builder = InstantiatingObjectParser.builder(
            "_xpack_security_playground_metric_proxy_request",
            false,
            MetricProxyRequest.class
        );
        builder.declareString(constructorArg(), new ParseField("path"));
        builder.declareString(optionalConstructorArg(), new ParseField("method"));
        final ObjectParserHelper<MetricProxyRequest, Void> objectParserHelper = new ObjectParserHelper<>();
        objectParserHelper.declareRawObjectOrNull(builder, optionalConstructorArg(), new ParseField("body"));
        PARSER = builder.build();
    }

    private static final Set<String> HTTP_METHODS = Set.of("GET", "POST", "PUT", "DELETE", "OPTIONS");

    public static class MetricProxyRequest {
        private final String path;
        private final String method;
        private final BytesReference body;

        public MetricProxyRequest(String path, String method, BytesReference body) {
            if (path.equals("/_security_playground/metric/proxy") || path.equals("_security_playground/metric/proxy")) {
                throw new IllegalArgumentException("cannot proxy the proxy API itself");
            }
            this.path = path;
            this.method = method == null ? "GET" : method.toUpperCase(Locale.ROOT);
            if (false == HTTP_METHODS.contains(this.method)) {
                throw new IllegalArgumentException("invalid HTTP method [{" + this.method + "}]");
            }
            this.body = body;
        }

        static MetricProxyRequest from(RestRequest restRequest) throws IOException {
            return PARSER.parse(restRequest.contentParser(), null);
        }
    }
}
