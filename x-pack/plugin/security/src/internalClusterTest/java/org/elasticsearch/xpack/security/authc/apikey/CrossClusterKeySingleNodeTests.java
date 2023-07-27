/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.apikey;

import org.elasticsearch.action.get.GetAction;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.support.PlainActionFuture;
import org.elasticsearch.test.SecuritySingleNodeTestCase;
import org.elasticsearch.test.XContentTestUtils;
import org.elasticsearch.transport.TcpTransport;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.core.security.action.apikey.CreateCrossClusterApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.apikey.CreateCrossClusterKeyAction;
import org.elasticsearch.xpack.core.security.action.apikey.CreateCrossClusterKeyResponse;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;

import java.io.IOException;
import java.util.Map;

import static org.elasticsearch.xpack.security.support.SecuritySystemIndices.SECURITY_MAIN_ALIAS;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;

public class CrossClusterKeySingleNodeTests extends SecuritySingleNodeTestCase {

    @Override
    protected boolean addMockHttpTransport() {
        return false;
    }

    public void testCreateCrossClusterKey() throws IOException {
        assumeTrue("untrusted remote cluster feature flag must be enabled", TcpTransport.isUntrustedRemoteClusterEnabled());

        final var request = CreateCrossClusterApiKeyRequest.withNameAndAccess(randomAlphaOfLengthBetween(3, 8), """
            {
              "search": [ {"names": ["logs"]} ]
            }""");

        final PlainActionFuture<CreateCrossClusterKeyResponse> future = new PlainActionFuture<>();
        client().execute(CreateCrossClusterKeyAction.INSTANCE, request, future);
        final CreateCrossClusterKeyResponse createCrossClusterKeyResponse = future.actionGet();

        final String keyId = createCrossClusterKeyResponse.getId();
        final String encoded = createCrossClusterKeyResponse.getEncoded();

        // Check the API key attributes with raw document
        final Map<String, Object> document = getCrossClusterKeyDocument(keyId);
        assertThat(document.get("doc_type"), equalTo("cross_cluster_key"));

        @SuppressWarnings("unchecked")
        final Map<String, Object> roleDescriptors = (Map<String, Object>) document.get("role_descriptors");
        assertThat(roleDescriptors.keySet(), contains("cross_cluster"));
        @SuppressWarnings("unchecked")
        final RoleDescriptor actualRoleDescriptor = RoleDescriptor.parse(
            "cross_cluster",
            XContentTestUtils.convertToXContent((Map<String, Object>) roleDescriptors.get("cross_cluster"), XContentType.JSON),
            false,
            XContentType.JSON
        );

        final RoleDescriptor expectedRoleDescriptor = new RoleDescriptor(
            "cross_cluster",
            new String[] { "cross_cluster_search" },
            new RoleDescriptor.IndicesPrivileges[] {
                RoleDescriptor.IndicesPrivileges.builder()
                    .indices("logs")
                    .privileges("read", "read_cross_cluster", "view_index_metadata")
                    .build() },
            null
        );
        assertThat(actualRoleDescriptor, equalTo(expectedRoleDescriptor));

        // // Check the API key attributes with Get API
        // final GetApiKeyResponse getApiKeyResponse = client().execute(
        // GetApiKeyAction.INSTANCE,
        // GetApiKeyRequest.builder().apiKeyId(keyId).withLimitedBy(randomBoolean()).build()
        // ).actionGet();
        // assertThat(getApiKeyResponse.getApiKeyInfos(), arrayWithSize(1));
        // final ApiKey getApiKeyInfo = getApiKeyResponse.getApiKeyInfos()[0];
        // assertThat(getApiKeyInfo.getType(), is(ApiKey.Type.CROSS_CLUSTER));
        // assertThat(getApiKeyInfo.getRoleDescriptors(), contains(expectedRoleDescriptor));
        // assertThat(getApiKeyInfo.getLimitedBy(), nullValue());
        // assertThat(getApiKeyInfo.getMetadata(), anEmptyMap());
        // assertThat(getApiKeyInfo.getUsername(), equalTo("test_user"));
        // assertThat(getApiKeyInfo.getRealm(), equalTo("file"));
    }

    private Map<String, Object> getCrossClusterKeyDocument(String keyId) {
        final GetResponse getResponse = client().execute(
            GetAction.INSTANCE,
            new GetRequest(SECURITY_MAIN_ALIAS, "cross_cluster_key_" + keyId)
        ).actionGet();
        return getResponse.getSource();
    }
}
