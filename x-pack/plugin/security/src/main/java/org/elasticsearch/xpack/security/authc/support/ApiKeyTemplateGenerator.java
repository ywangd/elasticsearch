/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authc.support;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyFromTemplateRequest;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyFromTemplateResponse;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyTemplateRequest;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyTemplateResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.support.DLSRoleQueryValidator;
import org.elasticsearch.xpack.security.authc.ApiKeyTemplateService;
import org.elasticsearch.xpack.security.authz.store.CompositeRolesStore;

import java.util.Arrays;
import java.util.HashSet;

public class ApiKeyTemplateGenerator {

    private final ApiKeyTemplateService apiKeyTemplateService;
    private final CompositeRolesStore rolesStore;
    private final NamedXContentRegistry xContentRegistry;

    public ApiKeyTemplateGenerator(ApiKeyTemplateService apiKeyTemplateService, CompositeRolesStore rolesStore, NamedXContentRegistry xContentRegistry) {
        this.apiKeyTemplateService = apiKeyTemplateService;
        this.rolesStore = rolesStore;
        this.xContentRegistry = xContentRegistry;
    }

    public void generateApiKeyTemplate(Authentication authentication, CreateApiKeyTemplateRequest request, ActionListener<CreateApiKeyTemplateResponse> listener) {
        if (authentication == null) {
            listener.onFailure(new ElasticsearchSecurityException("no authentication available to generate API key template"));
            return;
        }
        apiKeyTemplateService.ensureEnabled();
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
                    apiKeyTemplateService.createApiKeyTemplate(authentication, request, roleDescriptors, listener);
                },
                listener::onFailure));

    }

    public void generateApiKeyFromTemplate(
        Authentication authentication, CreateApiKeyFromTemplateRequest request, ActionListener<CreateApiKeyFromTemplateResponse> listener) {
        apiKeyTemplateService.ensureEnabled();
        apiKeyTemplateService.createApiKeyFromTemplate(authentication, request, listener);
    }
}
