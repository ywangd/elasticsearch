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
import org.elasticsearch.xpack.core.security.action.CreateApiKeyFromTemplateAction;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyFromTemplateRequest;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyFromTemplateResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.security.authc.ApiKeyTemplateService;
import org.elasticsearch.xpack.security.authc.support.ApiKeyTemplateGenerator;
import org.elasticsearch.xpack.security.authz.store.CompositeRolesStore;

/**
 * Implementation of the action needed to create an API key
 */
public final class TransportCreateApiKeyFromTemplateAction extends HandledTransportAction<CreateApiKeyFromTemplateRequest, CreateApiKeyFromTemplateResponse> {

    private final ApiKeyTemplateGenerator generator;
    private final SecurityContext securityContext;

    @Inject
    public TransportCreateApiKeyFromTemplateAction(TransportService transportService, ActionFilters actionFilters,
        ApiKeyTemplateService apiKeyTemplateService, SecurityContext context, CompositeRolesStore rolesStore,
        NamedXContentRegistry xContentRegistry) {
        super(CreateApiKeyFromTemplateAction.NAME, transportService, actionFilters, CreateApiKeyFromTemplateRequest::new);
        this.generator = new ApiKeyTemplateGenerator(apiKeyTemplateService, rolesStore, xContentRegistry);
        this.securityContext = context;
    }

    @Override
    protected void doExecute(Task task, CreateApiKeyFromTemplateRequest request, ActionListener<CreateApiKeyFromTemplateResponse> listener) {
        final Authentication authentication = securityContext.getAuthentication();
        if (authentication == null) {
            listener.onFailure(new IllegalStateException("authentication is required"));
        } else {
            generator.generateApiKeyFromTemplate(authentication, request, listener);
        }
    }
}
