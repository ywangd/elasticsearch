/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authc.support;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.support.DLSRoleQueryValidator;
import org.elasticsearch.xpack.security.authc.ApiKeyService;
import org.elasticsearch.xpack.security.authz.store.CompositeRolesStore;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.elasticsearch.index.mapper.MapperService.SINGLE_MAPPING_NAME;
import static org.elasticsearch.xpack.core.ClientHelper.SECURITY_ORIGIN;
import static org.elasticsearch.xpack.core.ClientHelper.executeAsyncWithOrigin;
import static org.elasticsearch.xpack.core.security.index.RestrictedIndicesNames.SECURITY_MAIN_ALIAS;

public class ApiKeyGenerator {

    private final ApiKeyService apiKeyService;
    private final CompositeRolesStore rolesStore;
    private final NamedXContentRegistry xContentRegistry;
    private final Client client;

    public ApiKeyGenerator(
        ApiKeyService apiKeyService, CompositeRolesStore rolesStore, NamedXContentRegistry xContentRegistry, Client client) {
        this.apiKeyService = apiKeyService;
        this.rolesStore = rolesStore;
        this.xContentRegistry = xContentRegistry;
        this.client = client;
    }

    public void generateApiKey(Authentication authentication, CreateApiKeyRequest request, ActionListener<CreateApiKeyResponse> listener) {
        if (authentication == null) {
            listener.onFailure(new ElasticsearchSecurityException("no authentication available to generate API key"));
            return;
        }
        apiKeyService.ensureEnabled();
        if (Authentication.AuthenticationType.API_KEY == authentication.getAuthenticationType()) {
            final String docId = (String) authentication.getMetadata().get(ApiKeyService.API_KEY_ID_KEY);
            final GetRequest getRequest = client
                .prepareGet(SECURITY_MAIN_ALIAS, SINGLE_MAPPING_NAME, docId)
                .setFetchSource(true)
                .request();
            executeAsyncWithOrigin(client.threadPool().getThreadContext(), SECURITY_ORIGIN, getRequest,
                ActionListener.<GetResponse>wrap(response -> {
                    final Map<String, Object> source = response.getSource();
                    client.threadPool().generic().execute(() -> generateNestedApiKey(authentication, request, source, listener));
                },
                e -> listener.onFailure(new IllegalStateException(e))),
                client::get);


        } else {
            rolesStore.getRoleDescriptors(new HashSet<>(Arrays.asList(authentication.getUser().roles())),
                ActionListener.wrap(roleDescriptors -> {
                        for (RoleDescriptor rd : roleDescriptors) {
                            try {
                                DLSRoleQueryValidator.validateQueryField(rd.getIndicesPrivileges(), xContentRegistry);
                            } catch (ElasticsearchException | IllegalArgumentException e) {
                                listener.onFailure(e);
                                return;
                            }
                        }
                        apiKeyService.createApiKey(authentication, request, Collections.singletonList(roleDescriptors), listener);
                    },
                    listener::onFailure));
        }

    }

    private void generateNestedApiKey(
        Authentication authentication, CreateApiKeyRequest request,
        Map<String, Object> source, ActionListener<CreateApiKeyResponse> listener) {

        final List<Set<RoleDescriptor>> listOfRoleDescriptors = new ArrayList<>();
        try {
            listOfRoleDescriptors.add(buildRoleDescriptorSet((Map<String, Object>) source.get("role_descriptors")));

            for (Map<String, Object> mapOfRoleDescriptors : (List<Map<String, Object>>) source.get("limited_by_role_descriptors")) {
                final Set<RoleDescriptor> roleDescriptors = buildRoleDescriptorSet(mapOfRoleDescriptors);
                listOfRoleDescriptors.add(roleDescriptors);
            }
        } catch (IOException e) {
            listener.onFailure(e);
            return;
        }

        for (Set<RoleDescriptor> roleDescriptors : listOfRoleDescriptors) {
            for (RoleDescriptor roleDescriptor : roleDescriptors) {
                try {
                    DLSRoleQueryValidator.validateQueryField(roleDescriptor.getIndicesPrivileges(), xContentRegistry);
                } catch (ElasticsearchException | IllegalArgumentException e) {
                    listener.onFailure(e);
                    return;
                }
            }
        }

        apiKeyService.createApiKey(authentication, request, listOfRoleDescriptors, listener);
    }

    private Set<RoleDescriptor> buildRoleDescriptorSet(Map<String, Object> mapOfRoleDescriptors) throws IOException {
        final HashSet<RoleDescriptor> roleDescriptors = new HashSet<>();
        for (Map.Entry<String, Object> entry : mapOfRoleDescriptors.entrySet()) {
            final RoleDescriptor roleDescriptor = RoleDescriptor.parse(
                entry.getKey(),
                BytesReference.bytes(XContentFactory.jsonBuilder().map((Map<String, Object>) entry.getValue())),
                false,
                XContentType.JSON);
            roleDescriptors.add(roleDescriptor);
        }
        return roleDescriptors;
    }


}
