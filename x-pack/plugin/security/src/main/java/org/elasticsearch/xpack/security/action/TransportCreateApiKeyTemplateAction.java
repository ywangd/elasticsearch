/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.action;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyTemplateAction;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyTemplateRequest;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyTemplateResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.security.authc.ApiKeyTemplateService;
import org.elasticsearch.xpack.security.authc.support.ApiKeyTemplateGenerator;
import org.elasticsearch.xpack.security.authz.store.CompositeRolesStore;

/**
 * Implementation of the action needed to create an API key
 */
public final class TransportCreateApiKeyTemplateAction extends HandledTransportAction<CreateApiKeyTemplateRequest, CreateApiKeyTemplateResponse> {

    private final ApiKeyTemplateGenerator generator;
    private final SecurityContext securityContext;

    @Inject
    public TransportCreateApiKeyTemplateAction(TransportService transportService, ActionFilters actionFilters,
        ApiKeyTemplateService apiKeyTemplateService, SecurityContext context, CompositeRolesStore rolesStore,
        NamedXContentRegistry xContentRegistry) {
        super(CreateApiKeyTemplateAction.NAME, transportService, actionFilters, CreateApiKeyTemplateRequest::new);
        this.generator = new ApiKeyTemplateGenerator(apiKeyTemplateService, rolesStore, xContentRegistry);
        this.securityContext = context;
    }

    @Override
    protected void doExecute(Task task, CreateApiKeyTemplateRequest request, ActionListener<CreateApiKeyTemplateResponse> listener) {
        final Authentication authentication = securityContext.getAuthentication();
        if (authentication == null) {
            listener.onFailure(new IllegalStateException("authentication is required"));
        } else {
            if (Authentication.AuthenticationType.API_KEY == authentication.getAuthenticationType() && grantsAnyPrivileges(request)) {
                listener.onFailure(new IllegalArgumentException(
                    "creating derived api keys requires an explicit role descriptor that is empty (has no privileges)"));
                return;
            }
            generator.generateApiKeyTemplate(authentication, request, listener);
        }
    }

    private boolean grantsAnyPrivileges(CreateApiKeyTemplateRequest request) {
        return request.getRoleDescriptors() == null
            || request.getRoleDescriptors().isEmpty()
            || false == request.getRoleDescriptors().stream().allMatch(RoleDescriptor::isEmpty);
    }
}
