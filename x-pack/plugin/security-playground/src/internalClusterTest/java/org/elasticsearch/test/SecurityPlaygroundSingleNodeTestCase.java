/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.test;

import io.netty.util.ThreadDeathWatcher;
import io.netty.util.concurrent.GlobalEventExecutor;

import org.apache.http.HttpHost;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.action.admin.cluster.node.info.PluginsAndModules;
import org.elasticsearch.analysis.common.CommonAnalysisPlugin;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.common.network.NetworkAddress;
import org.elasticsearch.common.settings.MockSecureSettings;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.core.internal.io.IOUtils;
import org.elasticsearch.http.HttpInfo;
import org.elasticsearch.index.reindex.ReindexPlugin;
import org.elasticsearch.license.LicenseService;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.plugins.PluginInfo;
import org.elasticsearch.transport.Netty4Plugin;
import org.elasticsearch.xpack.core.security.authc.support.Hasher;
import org.elasticsearch.xpack.security.playground.LocalStateSecurityPlayground;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.rules.ExternalResource;

import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.elasticsearch.test.SecuritySettingsSourceField.TEST_PASSWORD_SECURE_STRING;
import static org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken.basicAuthHeaderValue;
import static org.elasticsearch.xpack.security.test.SecurityTestUtils.writeFile;
import static org.hamcrest.Matchers.hasItem;

public abstract class SecurityPlaygroundSingleNodeTestCase extends ESSingleNodeTestCase {

    private static SecuritySettingsSource SECURITY_DEFAULT_SETTINGS = null;
    private static CustomSecuritySettingsSource customSecuritySettingsSource = null;
    private static RestClient restClient = null;
    private static SecureString BOOTSTRAP_PASSWORD = null;
    private static final String INDEX_ABSTRACTIONS = "{\"metadata\": {\"indices\": {\"index\": {\"state\": \"open\", "
        + "\"settings\": {\"hidden\": false}, \"aliases\": [\"alias_indices\", "
        + "\"my-write-alias\"], \"system\": false}, \".ds-ilm-history-5-2021.08.01-000001\": "
        + "{\"state\": \"open\", \"settings\": {\"hidden\": \"true\"}, \"aliases\": [], \"system\": false}, "
        + "\".ds-my-data-stream-2021.08.01-000001\": {\"state\": \"open\", \"settings\": {\"hidden\": \"true\"}, "
        + "\"aliases\": [], \"system\": false}, \".security-7\": {\"state\": \"open\", "
        + "\"settings\": {\"hidden\": false}, \"aliases\": [\".security\"], \"system\": true}}, "
        + "\"data_stream\": {\"data_stream\": {\"ilm-history-5\": {\"indices\": [{\"index_name\": "
        + "\".ds-ilm-history-5-2021.08.01-000001\"}], \"hidden\": true, \"system\": false}, "
        + "\"my-data-stream\": {\"indices\": [{\"index_name\": \".ds-my-data-stream-2021.08.01-000001\"}], "
        + "\"hidden\": false, \"system\": false}}, \"data_stream_aliases\": "
        + "{\"alias_data_streams\": {\"data_streams\": [\"my-data-stream\"]}}}}}\n";

    @BeforeClass
    public static void generateBootstrapPassword() {
        BOOTSTRAP_PASSWORD = TEST_PASSWORD_SECURE_STRING.clone();
    }

    @BeforeClass
    public static void initDefaultSettings() {
        if (SECURITY_DEFAULT_SETTINGS == null) {
            SECURITY_DEFAULT_SETTINGS = new SecuritySettingsSource(randomBoolean(), createTempDir(), ESIntegTestCase.Scope.SUITE);
        }
    }

    /**
     * Set the static default settings to null to prevent a memory leak. The test framework also checks for memory leaks
     * and computes the size, this can cause issues when running with the security manager as it tries to do reflection
     * into protected sun packages.
     */
    @AfterClass
    public static void destroyDefaultSettings() {
        SECURITY_DEFAULT_SETTINGS = null;
        customSecuritySettingsSource = null;
        if (BOOTSTRAP_PASSWORD != null) {
            BOOTSTRAP_PASSWORD.close();
            BOOTSTRAP_PASSWORD = null;
        }
        tearDownRestClient();
    }

    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        if (resetNodeAfterTest()) {
            tearDownRestClient();
        }
    }

    private static void tearDownRestClient() {
        if (restClient != null) {
            IOUtils.closeWhileHandlingException(restClient);
            restClient = null;
        }
    }

    @Rule
    // Rules are the only way to have something run before the before (final) method inherited from ESSingleNodeTestCase
    public ExternalResource externalResource = new ExternalResource() {
        @Override
        protected void before() {
            if (customSecuritySettingsSource == null) {
                customSecuritySettingsSource = new CustomSecuritySettingsSource(
                    transportSSLEnabled(),
                    createTempDir(),
                    ESIntegTestCase.Scope.SUITE
                );
            }
        }
    };

    /**
     * A JUnit class level rule that runs after the AfterClass method in {@link ESIntegTestCase},
     * which stops the cluster. After the cluster is stopped, there are a few netty threads that
     * can linger, so we wait for them to finish otherwise these lingering threads can intermittently
     * trigger the thread leak detector
     */
    @ClassRule
    public static final ExternalResource STOP_NETTY_RESOURCE = new ExternalResource() {
        @Override
        protected void after() {
            try {
                GlobalEventExecutor.INSTANCE.awaitInactivity(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IllegalStateException e) {
                if (e.getMessage().equals("thread was not started") == false) {
                    throw e;
                }
                // ignore since the thread was never started
            }

            try {
                ThreadDeathWatcher.awaitInactivity(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    };

    @Before
    // before methods from the superclass are run before this, which means that the current cluster is ready to go
    public void assertXPackIsInstalled() {
        doAssertXPackIsInstalled();
    }

    private void doAssertXPackIsInstalled() {
        NodesInfoResponse nodeInfos = client().admin().cluster().prepareNodesInfo().clear().setPlugins(true).get();
        for (NodeInfo nodeInfo : nodeInfos.getNodes()) {
            // TODO: disable this assertion for now, due to random runs with mock plugins. perhaps run without mock plugins?
            // assertThat(nodeInfo.getInfo(PluginsAndModules.class).getInfos(), hasSize(2));
            Collection<String> pluginNames = nodeInfo.getInfo(PluginsAndModules.class)
                .getPluginInfos()
                .stream()
                .map(PluginInfo::getClassname)
                .collect(Collectors.toList());
            assertThat(
                "plugin [" + LocalStateSecurityPlayground.class.getName() + "] not found in [" + pluginNames + "]",
                pluginNames,
                hasItem(LocalStateSecurityPlayground.class.getName())
            );
        }
    }

    @Override
    protected Settings nodeSettings() {
        final Path home = customSecuritySettingsSource.nodePath(0);

        Settings.Builder builder = Settings.builder().put(super.nodeSettings());
        Settings customSettings = customSecuritySettingsSource.nodeSettings(0, Settings.EMPTY);
        builder.put(customSettings, false); // handle secure settings separately
        builder.put(LicenseService.SELF_GENERATED_LICENSE_TYPE.getKey(), "trial");
        builder.put("transport.type", "security4");
        builder.put("path.home", home);
        Settings.Builder customBuilder = Settings.builder().put(customSettings);
        if (customBuilder.getSecureSettings() != null) {
            SecuritySettingsSource.addSecureSettings(
                builder,
                secureSettings -> secureSettings.merge((MockSecureSettings) customBuilder.getSecureSettings())
            );
        }
        if (builder.getSecureSettings() == null) {
            builder.setSecureSettings(new MockSecureSettings());
        }
        ((MockSecureSettings) builder.getSecureSettings()).setString("bootstrap.password", BOOTSTRAP_PASSWORD.toString());
        final Settings settings = builder.build();

        final Path xpackConf = home.resolve("config");
        writeFile(xpackConf, "index_abstractions.json", INDEX_ABSTRACTIONS);

        return settings;
    }

    @Override
    protected boolean addMockHttpTransport() {
        return false;
    }

    @Override
    protected Collection<Class<? extends Plugin>> getPlugins() {
        return Arrays.asList(
            LocalStateSecurityPlayground.class,
            Netty4Plugin.class,
            ReindexPlugin.class,
            CommonAnalysisPlugin.class,
            InternalSettingsPlugin.class
        );
    }

    /**
     * Allows to override the users config file
     */
    protected String configUsers() {
        return SECURITY_DEFAULT_SETTINGS.configUsers();
    }

    /**
     * Allows to override the users_roles config file
     */
    protected String configUsersRoles() {
        return SECURITY_DEFAULT_SETTINGS.configUsersRoles();
    }

    /**
     * Allows to override the roles config file
     */
    protected String configRoles() {
        return SECURITY_DEFAULT_SETTINGS.configRoles();
    }

    protected String configOperatorUsers() {
        return SECURITY_DEFAULT_SETTINGS.configOperatorUsers();
    }

    protected String configServiceTokens() {
        return SECURITY_DEFAULT_SETTINGS.configServiceTokens();
    }

    /**
     * Allows to override the node client username
     */
    protected String nodeClientUsername() {
        return SECURITY_DEFAULT_SETTINGS.nodeClientUsername();
    }

    /**
     * Allows to override the node client password (used while sending requests to the test node)
     */
    protected SecureString nodeClientPassword() {
        return SECURITY_DEFAULT_SETTINGS.nodeClientPassword();
    }

    /**
     * Allows to control whether ssl key information is auto generated or not on the transport layer
     */
    protected boolean transportSSLEnabled() {
        return randomBoolean();
    }

    private class CustomSecuritySettingsSource extends SecuritySettingsSource {

        private CustomSecuritySettingsSource(boolean sslEnabled, Path configDir, ESIntegTestCase.Scope scope) {
            super(sslEnabled, configDir, scope);
        }

        @Override
        protected String configUsers() {
            return SecurityPlaygroundSingleNodeTestCase.this.configUsers();
        }

        @Override
        protected String configUsersRoles() {
            return SecurityPlaygroundSingleNodeTestCase.this.configUsersRoles();
        }

        @Override
        protected String configRoles() {
            return SecurityPlaygroundSingleNodeTestCase.this.configRoles();
        }

        @Override
        protected String configOperatorUsers() {
            return SecurityPlaygroundSingleNodeTestCase.this.configOperatorUsers();
        }

        @Override
        protected String configServiceTokens() {
            return SecurityPlaygroundSingleNodeTestCase.this.configServiceTokens();
        }

        @Override
        protected String nodeClientUsername() {
            return SecurityPlaygroundSingleNodeTestCase.this.nodeClientUsername();
        }

        @Override
        protected SecureString nodeClientPassword() {
            return SecurityPlaygroundSingleNodeTestCase.this.nodeClientPassword();
        }
    }

    @Override
    public Client wrapClient(final Client client) {
        Map<String, String> headers = Collections.singletonMap(
            "Authorization",
            basicAuthHeaderValue(nodeClientUsername(), nodeClientPassword())
        );
        // we need to wrap node clients because we do not specify a user for nodes and all requests will use the system
        // user. This is ok for internal n2n stuff but the test framework does other things like wiping indices, repositories, etc
        // that the system user cannot do. so we wrap the node client with a user that can do these things since the client() calls
        // are all using a node client
        return client.filterWithHeader(headers);
    }

    protected boolean isTransportSSLEnabled() {
        return customSecuritySettingsSource.isSslEnabled();
    }

    /**
     * Returns an instance of {@link RestClient} pointing to the current node.
     * Creates a new client if the method is invoked for the first time in the context of the current test scope.
     * The returned client gets automatically closed when needed, it shouldn't be closed as part of tests otherwise
     * it cannot be reused by other tests anymore.
     */
    protected RestClient getRestClient() {
        return getRestClient(client());
    }

    protected RestClient createRestClient(RestClientBuilder.HttpClientConfigCallback httpClientConfigCallback, String protocol) {
        return createRestClient(client(), httpClientConfigCallback, protocol);
    }

    protected static Hasher getFastStoredHashAlgoForTests() {
        return inFipsJvm()
            ? Hasher.resolve(randomFrom("pbkdf2", "pbkdf2_1000", "pbkdf2_stretch_1000", "pbkdf2_stretch"))
            : Hasher.resolve(randomFrom("pbkdf2", "pbkdf2_1000", "pbkdf2_stretch_1000", "pbkdf2_stretch", "bcrypt", "bcrypt9"));
    }

    private static synchronized RestClient getRestClient(Client client) {
        if (restClient == null) {
            restClient = createRestClient(client, null, "http");
        }
        return restClient;
    }

    private static RestClient createRestClient(
        Client client,
        RestClientBuilder.HttpClientConfigCallback httpClientConfigCallback,
        String protocol
    ) {
        NodesInfoResponse nodesInfoResponse = client.admin().cluster().prepareNodesInfo().get();
        assertFalse(nodesInfoResponse.hasFailures());
        assertEquals(nodesInfoResponse.getNodes().size(), 1);
        NodeInfo node = nodesInfoResponse.getNodes().get(0);
        assertNotNull(node.getInfo(HttpInfo.class));
        TransportAddress publishAddress = node.getInfo(HttpInfo.class).address().publishAddress();
        InetSocketAddress address = publishAddress.address();
        final HttpHost host = new HttpHost(NetworkAddress.format(address.getAddress()), address.getPort(), protocol);
        RestClientBuilder builder = RestClient.builder(host);
        if (httpClientConfigCallback != null) {
            builder.setHttpClientConfigCallback(httpClientConfigCallback);
        }
        return builder.build();
    }
}
