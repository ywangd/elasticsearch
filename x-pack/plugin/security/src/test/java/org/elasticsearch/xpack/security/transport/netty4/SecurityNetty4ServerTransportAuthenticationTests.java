/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.transport.netty4;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.TransportVersion;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.node.DiscoveryNodeRole;
import org.elasticsearch.cluster.node.VersionInformation;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.MockSecureSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.PageCacheRecycler;
import org.elasticsearch.core.IOUtils;
import org.elasticsearch.indices.breaker.NoneCircuitBreakerService;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.NodeRoles;
import org.elasticsearch.test.transport.MockTransportService;
import org.elasticsearch.threadpool.TestThreadPool;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.ProxyConnectionStrategy;
import org.elasticsearch.transport.RemoteClusterPortSettings;
import org.elasticsearch.transport.RemoteClusterService;
import org.elasticsearch.transport.RemoteConnectionStrategy;
import org.elasticsearch.transport.SniffConnectionStrategy;
import org.elasticsearch.transport.TransportInterceptor;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.netty4.SharedGroupFactory;
import org.elasticsearch.xpack.core.XPackSettings;
import org.elasticsearch.xpack.core.ssl.SSLService;
import org.elasticsearch.xpack.security.authc.CrossClusterAccessAuthenticationService;
import org.junit.After;
import org.junit.Before;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.elasticsearch.test.ActionListenerUtils.anyActionListener;
import static org.elasticsearch.test.NodeRoles.onlyRole;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

public class SecurityNetty4ServerTransportAuthenticationTests extends ESTestCase {

    private ThreadPool threadPool;
    private String remoteClusterName;
    private SecurityNetty4ServerTransport remoteSecurityNetty4ServerTransport;
    private MockTransportService remoteTransportService;
    private CrossClusterAccessAuthenticationService remoteCrossClusterAccessAuthenticationService;
    private final AtomicReference<Set<String>> actionsShouldPassRegularAuthn = new AtomicReference<>();

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        threadPool = new TestThreadPool(getClass().getName());
        remoteClusterName = "test-remote_cluster_service_" + randomAlphaOfLength(8);
        Settings remoteSettings = Settings.builder()
            .put("node.name", getClass().getName())
            .put(ClusterName.CLUSTER_NAME_SETTING.getKey(), remoteClusterName)
            .put(XPackSettings.TRANSPORT_SSL_ENABLED.getKey(), "false")
            .put(XPackSettings.REMOTE_CLUSTER_SERVER_SSL_ENABLED.getKey(), "false")
            .put(XPackSettings.REMOTE_CLUSTER_CLIENT_SSL_ENABLED.getKey(), "false")
            .put(RemoteClusterPortSettings.REMOTE_CLUSTER_SERVER_ENABLED.getKey(), "true")
            .put(RemoteClusterPortSettings.PORT.getKey(), "0")
            .build();
        remoteSettings = NodeRoles.nonRemoteClusterClientNode(remoteSettings);
        remoteCrossClusterAccessAuthenticationService = mock(CrossClusterAccessAuthenticationService.class);
        remoteSecurityNetty4ServerTransport = new SecurityNetty4ServerTransport(
            remoteSettings,
            TransportVersion.current(),
            threadPool,
            new NetworkService(List.of()),
            PageCacheRecycler.NON_RECYCLING_INSTANCE,
            new NamedWriteableRegistry(List.of()),
            new NoneCircuitBreakerService(),
            null,
            mock(SSLService.class),
            new SharedGroupFactory(remoteSettings),
            remoteCrossClusterAccessAuthenticationService
        );
        actionsShouldPassRegularAuthn.set(Set.of());
        remoteTransportService = MockTransportService.createNewService(
            remoteSettings,
            remoteSecurityNetty4ServerTransport,
            VersionInformation.CURRENT,
            threadPool,
            null,
            Collections.emptySet(),
            new TransportInterceptor() {
                @Override
                public <T extends TransportRequest> TransportRequestHandler<T> interceptHandler(
                    String action,
                    String executor,
                    boolean forceExecution,
                    TransportRequestHandler<T> actualHandler
                ) {
                    return (request, channel, task) -> {
                        if (actionsShouldPassRegularAuthn.get().contains(action)) {
                            actualHandler.messageReceived(request, channel, task);
                        } else {
                            channel.sendResponse(new ElasticsearchSecurityException("regular authentication failure"));
                        }
                    };
                }
            }
        );
        remoteTransportService.start();
        remoteTransportService.acceptIncomingRequests();
    }

    @Override
    @After
    public void tearDown() throws Exception {
        logger.info("tearDown");
        super.tearDown();
        IOUtils.close(
            remoteTransportService,
            remoteSecurityNetty4ServerTransport,
            () -> ThreadPool.terminate(threadPool, 10, TimeUnit.SECONDS)
        );
    }

    @SuppressWarnings("unchecked")
    public void testProxyStrategyConnectionClosesWhenAuthenticatorAlwaysFails() throws Exception {
        // all requests fail authn
        doAnswer(invocation -> {
            ((ActionListener<Void>) invocation.getArguments()[1]).onFailure(new ElasticsearchSecurityException("failed authn"));
            return null;
        }).when(remoteCrossClusterAccessAuthenticationService).tryAuthenticate(any(Map.class), anyActionListener());
        Settings localSettings = Settings.builder()
            .put(onlyRole(DiscoveryNodeRole.REMOTE_CLUSTER_CLIENT_ROLE))
            .put(RemoteConnectionStrategy.REMOTE_CONNECTION_MODE.getConcreteSettingForNamespace(remoteClusterName).getKey(), "proxy")
            .put(
                ProxyConnectionStrategy.PROXY_ADDRESS.getConcreteSettingForNamespace(remoteClusterName).getKey(),
                remoteTransportService.boundRemoteAccessAddress().publishAddress().toString()
            )
            .put(
                ProxyConnectionStrategy.REMOTE_SOCKET_CONNECTIONS.getConcreteSettingForNamespace(remoteClusterName).getKey(),
                randomIntBetween(1, 3) // easier to debug with just 1 connection
            )
            .build();
        {
            final MockSecureSettings secureSettings = new MockSecureSettings();
            secureSettings.setString(
                RemoteClusterService.REMOTE_CLUSTER_CREDENTIALS.getConcreteSettingForNamespace(remoteClusterName).getKey(),
                randomAlphaOfLength(20)
            );
            localSettings = Settings.builder().put(localSettings).setSecureSettings(secureSettings).build();
        }
        try (
            MockTransportService localService = MockTransportService.createNewService(
                localSettings,
                VersionInformation.CURRENT,
                TransportVersion.current(),
                threadPool
            )
        ) {
            localService.start();
            RemoteClusterService remoteClusterService = localService.getRemoteClusterService();
            // obtain some connections and check that they'll be promptly closed
            for (int i = 0; i < randomIntBetween(4, 16); i++) {
                CountDownLatch connectionTestDone = new CountDownLatch(1);
                // Proxy connection validates cluster name before report success. Cluster name validation will fail because it needs authn
                remoteClusterService.maybeEnsureConnectedAndGetConnection(remoteClusterName, true, ActionListener.wrap(connection -> {
                    fail("No connection should be available");
                }, e -> {
                    logger.info("A connection could not be established");
                    connectionTestDone.countDown();
                }));
                assertTrue(connectionTestDone.await(10L, TimeUnit.SECONDS));
            }
        }
    }

    @SuppressWarnings("unchecked")
    public void testSniffStrategyNoConnectionWhenAuthenticatorAlwaysFails() throws Exception {
        // all requests fail authn
        doAnswer(invocation -> {
            ((ActionListener<Void>) invocation.getArguments()[1]).onFailure(new ElasticsearchSecurityException("failed authn"));
            return null;
        }).when(remoteCrossClusterAccessAuthenticationService).tryAuthenticate(any(Map.class), anyActionListener());
        Settings localSettings = Settings.builder()
            .put(onlyRole(DiscoveryNodeRole.REMOTE_CLUSTER_CLIENT_ROLE))
            .put(RemoteConnectionStrategy.REMOTE_CONNECTION_MODE.getConcreteSettingForNamespace(remoteClusterName).getKey(), "sniff")
            .put(
                SniffConnectionStrategy.REMOTE_CLUSTER_SEEDS.getConcreteSettingForNamespace(remoteClusterName).getKey(),
                remoteTransportService.boundRemoteAccessAddress().publishAddress().toString()
            )
            .put(
                SniffConnectionStrategy.REMOTE_CONNECTIONS_PER_CLUSTER.getKey(),
                randomIntBetween(1, 3) // easier to debug with just 1 connection
            )
            .put(
                SniffConnectionStrategy.REMOTE_NODE_CONNECTIONS.getConcreteSettingForNamespace(remoteClusterName).getKey(),
                randomIntBetween(1, 3) // easier to debug with just 1 connection
            )
            .build();
        {
            final MockSecureSettings secureSettings = new MockSecureSettings();
            secureSettings.setString(
                RemoteClusterService.REMOTE_CLUSTER_CREDENTIALS.getConcreteSettingForNamespace(remoteClusterName).getKey(),
                randomAlphaOfLength(20)
            );
            localSettings = Settings.builder().put(localSettings).setSecureSettings(secureSettings).build();
        }
        try (
            MockTransportService localService = MockTransportService.createNewService(
                localSettings,
                VersionInformation.CURRENT,
                TransportVersion.current(),
                threadPool
            )
        ) {
            localService.start();
            RemoteClusterService remoteClusterService = localService.getRemoteClusterService();
            // obtain some connections and check that they'll be promptly closed
            for (int i = 0; i < randomIntBetween(4, 16); i++) {
                CountDownLatch connectionTestDone = new CountDownLatch(1);
                // the failed authentication during handshake must surely close the connection before
                // {@code RemoteClusterNodesAction.NAME} is executed, so node sniffing will fail
                remoteClusterService.maybeEnsureConnectedAndGetConnection(remoteClusterName, true, ActionListener.wrap(connection -> {
                    fail("No connection should be available, because node sniffing should fail on connection closed");
                }, e -> {
                    logger.info("No connection could be established");
                    connectionTestDone.countDown();
                }));
                assertTrue(connectionTestDone.await(10L, TimeUnit.SECONDS));
            }
        }
    }

}
