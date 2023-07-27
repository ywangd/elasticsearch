/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.apikey;

import org.elasticsearch.client.Request;
import org.elasticsearch.client.ResponseException;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.test.rest.ObjectPath;
import org.elasticsearch.transport.TcpTransport;
import org.elasticsearch.xcontent.json.JsonXContent;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;
import org.elasticsearch.xpack.security.SecurityOnTrialLicenseRestTestCase;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

/**
 * Integration Rest Tests relating to API Keys.
 * Tested against a trial license
 */
public class CrossClusterKeyRestIT extends SecurityOnTrialLicenseRestTestCase {

    private static final String SYSTEM_USER = "system_user";
    private static final SecureString SYSTEM_USER_PASSWORD = new SecureString("system-user-password".toCharArray());
    private static final String END_USER = "end_user";
    private static final SecureString END_USER_PASSWORD = new SecureString("end-user-password".toCharArray());
    private static final String MANAGE_SECURITY_USER = "manage_security_user";

    @Before
    public void createUsers() throws IOException {
        createUser(SYSTEM_USER, SYSTEM_USER_PASSWORD, List.of("system_role"));
        createRole("system_role", Set.of("grant_api_key"));
        createUser(END_USER, END_USER_PASSWORD, List.of("user_role"));
        createRole("user_role", Set.of("monitor"));
        createRole("manage_own_api_key_role", Set.of("manage_own_api_key"));
        createRole("manage_api_key_role", Set.of("manage_api_key"));
        createUser(MANAGE_SECURITY_USER, END_USER_PASSWORD, List.of("manage_security_role"));
        createRole("manage_security_role", Set.of("manage_security"));
    }

    @After
    public void cleanUp() throws IOException {
        deleteUser(SYSTEM_USER);
        deleteUser(END_USER);
        deleteUser(MANAGE_SECURITY_USER);
        deleteRole("system_role");
        deleteRole("user_role");
        deleteRole("manage_security_role");
        invalidateApiKeysForUser(END_USER);
        invalidateApiKeysForUser(MANAGE_SECURITY_USER);
    }

    public void testCreateCrossClusterApiKey() throws IOException {
        assumeTrue("untrusted remote cluster feature flag must be enabled", TcpTransport.isUntrustedRemoteClusterEnabled());

        final Request createRequest = new Request("POST", "/_security/cross_cluster_key");
        createRequest.setJsonEntity("""
            {
              "name": "my-key",
              "access": {
                "search": [
                  {
                    "names": [ "metrics" ],
                    "query": "{\\"term\\":{\\"score\\":42}}"
                  }
                ],
                "replication": [
                  {
                    "names": [ "logs" ],
                    "allow_restricted_indices": true
                  }
                ]
              },
              "expiration": "7d",
              "metadata": { "tag": "shared", "points": 0 }
            }""");
        setUserForRequest(createRequest, MANAGE_SECURITY_USER, END_USER_PASSWORD);

        final ObjectPath createResponse = assertOKAndCreateObjectPath(client().performRequest(createRequest));
        final String keyId = createResponse.evaluate("id");

        final ObjectPath fetchResponse = fetchCrossClusterKeyById(keyId);
        assertThat(fetchResponse.evaluate("cross_cluster_keys.0.access"), equalTo(XContentHelper.convertToMap(JsonXContent.jsonXContent, """
            {
                "search": [
                  {
                    "names": [
                      "metrics"
                    ],
                    "query": "{\\"term\\":{\\"score\\":42}}",
                    "allow_restricted_indices": false
                  }
                ],
                "replication": [
                  {
                    "names": [
                      "logs"
                    ],
                    "allow_restricted_indices": true
                  }
                ]

            }""", false)));
    }

    public void testCrossClusterApiKeyDoesNotAllowEmptyAccess() throws IOException {
        assumeTrue("untrusted remote cluster feature flag must be enabled", TcpTransport.isUntrustedRemoteClusterEnabled());

        assertBadCreateCrossClusterApiKeyRequest("""
            {"name": "my-key"}""", "Required [access]");

        assertBadCreateCrossClusterApiKeyRequest("""
            {"name": "my-key", "access": null}""", "access doesn't support values of type: VALUE_NULL");

        assertBadCreateCrossClusterApiKeyRequest("""
            {"name": "my-key", "access": {}}}""", "must specify non-empty access for either [search] or [replication]");

        assertBadCreateCrossClusterApiKeyRequest("""
            {"name": "my-key", "access": {"search":[]}}}""", "must specify non-empty access for either [search] or [replication]");

        assertBadCreateCrossClusterApiKeyRequest("""
            {"name": "my-key", "access": {"replication":[]}}}""", "must specify non-empty access for either [search] or [replication]");

        assertBadCreateCrossClusterApiKeyRequest(
            """
                {"name": "my-key", "access": {"search":[],"replication":[]}}}""",
            "must specify non-empty access for either [search] or [replication]"
        );
    }

    public void testCrossClusterApiKeyDoesNotAllowDlsFlsForReplication() throws IOException {
        assumeTrue("untrusted remote cluster feature flag must be enabled", TcpTransport.isUntrustedRemoteClusterEnabled());

        assertBadCreateCrossClusterApiKeyRequest("""
            {
              "name": "key",
              "access": {
                "replication": [ {"names": ["logs"], "query":{"term": {"tag": 42}}} ]
              }
            }""", "replication does not support document or field level security");

        assertBadCreateCrossClusterApiKeyRequest("""
            {
              "name": "key",
              "access": {
                "replication": [ {"names": ["logs"], "field_security": {"grant": ["*"], "except": ["private"]}} ]
              }
            }""", "replication does not support document or field level security");

        assertBadCreateCrossClusterApiKeyRequest("""
            {
              "name": "key",
              "access": {
                "replication": [ {
                  "names": ["logs"],
                  "query": {"term": {"tag": 42}},
                  "field_security": {"grant": ["*"], "except": ["private"]}
                 } ]
              }
            }""", "replication does not support document or field level security");
    }

    public void testCrossClusterApiKeyRequiresName() throws IOException {
        assumeTrue("untrusted remote cluster feature flag must be enabled", TcpTransport.isUntrustedRemoteClusterEnabled());

        assertBadCreateCrossClusterApiKeyRequest("""
            {
              "access": {
                "search": [ {"names": ["logs"]} ]
              }
            }""", "Required [name]");
    }

    private ObjectPath fetchCrossClusterKeyById(String keyId) throws IOException {
        final Request fetchRequest;
        fetchRequest = new Request("GET", "/_security/cross_cluster_key/" + keyId);
        setUserForRequest(fetchRequest, MANAGE_SECURITY_USER, END_USER_PASSWORD);
        final ObjectPath fetchResponse = assertOKAndCreateObjectPath(client().performRequest(fetchRequest));
        assertThat(fetchResponse.evaluate("cross_cluster_keys.0.id"), equalTo(keyId));
        assertThat(fetchResponse.evaluate("cross_cluster_keys.0.access"), notNullValue());
        return fetchResponse;
    }

    private void assertBadCreateCrossClusterApiKeyRequest(String body, String expectedErrorMessage) throws IOException {
        final Request createRequest = new Request("POST", "/_security/cross_cluster_key");
        createRequest.setJsonEntity(body);
        setUserForRequest(createRequest, MANAGE_SECURITY_USER, END_USER_PASSWORD);
        final ResponseException e = expectThrows(ResponseException.class, () -> client().performRequest(createRequest));
        assertThat(e.getResponse().getStatusLine().getStatusCode(), equalTo(400));
        assertThat(e.getMessage(), containsString(expectedErrorMessage));
    }

    private void setUserForRequest(Request request, String username, SecureString password) throws IOException {
        request.setOptions(
            request.getOptions()
                .toBuilder()
                .removeHeader("Authorization")
                .addHeader("Authorization", headerFromRandomAuthMethod(username, password))
        );
    }

    private String headerFromRandomAuthMethod(final String username, final SecureString password) throws IOException {
        final boolean useBearerTokenAuth = randomBoolean();
        if (useBearerTokenAuth) {
            final Tuple<String, String> token = super.createOAuthToken(username, password);
            return "Bearer " + token.v1();
        } else {
            return UsernamePasswordToken.basicAuthHeaderValue(username, password);
        }
    }
}
