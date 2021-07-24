/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground;

import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.ssl.SSLContexts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.network.NetworkAddress;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.http.HttpInfo;
import org.elasticsearch.xpack.security.playground.actions.TransportSPClusterAction;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;

public class RestClientComponent extends AbstractLifecycleComponent {

    private static final Logger logger = LogManager.getLogger(RestClientComponent.class);

    private final boolean sslEnabled;
    private volatile RestClient restClient;

    public RestClientComponent(Settings settings) {
        sslEnabled = settings.getAsBoolean("xpack.security.http.ssl.enabled", false);
    }

    public Response performRequest(Request request) throws IOException {
        return getRestClient().performRequest(request);
    }

    private RestClient getRestClient() {
        if (restClient == null) {
            synchronized (this) {
                if (restClient == null) {
                    if (TransportSPClusterAction.nodeService == null) {
                        throw new IllegalStateException("_security_playground/proxy not ready yet");
                    }
                    final NodeInfo node = TransportSPClusterAction.nodeService.info(
                        false,
                        false,
                        false,
                        false,
                        false,
                        false,
                        true,
                        false,
                        false,
                        false,
                        false
                    );

                    TransportAddress publishAddress = node.getInfo(HttpInfo.class).address().publishAddress();
                    InetSocketAddress address = publishAddress.address();
                    final HttpHost host = new HttpHost(
                        NetworkAddress.format(address.getAddress()),
                        address.getPort(),
                        sslEnabled ? "https" : "http"
                    );
                    logger.trace("target host for rest client is [{}]", host);
                    RestClientBuilder builder = RestClient.builder(host);
                    if (sslEnabled) {
                        final SSLContext sslContext;
                        try {
                            sslContext = SSLContexts.custom().loadTrustMaterial(TrustAllStrategy.INSTANCE).build();
                        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException e) {
                            throw new ElasticsearchException(e);
                        }
                        // TODO: proper HTTPS instead of skipping?
                        builder.setHttpClientConfigCallback(
                            httpClientBuilder -> httpClientBuilder.setSSLContext(sslContext)
                                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                        );
                    }
                    // TODO: no timeout?
                    restClient = builder.build();
                }
            }
        }
        return restClient;
    }

    @Override
    protected void doStart() {

    }

    @Override
    protected void doStop() {

    }

    @Override
    protected void doClose() throws IOException {
        if (restClient != null) {
            restClient.close();
        }
    }
}
