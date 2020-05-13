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
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.core.security.action.SyncApiKeyAction;
import org.elasticsearch.xpack.core.security.action.SyncApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.SyncApiKeyResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.security.authc.ApiKeyService;
import org.elasticsearch.xpack.security.authc.ApiKeyTemplateService;

/**
 * Implementation of the action needed to create an API key
 */
public final class TransportSyncApiKeyAction extends HandledTransportAction<SyncApiKeyRequest, SyncApiKeyResponse> {

    private final ApiKeyTemplateService apiKeyTemplateService;
    private final SecurityContext securityContext;

    @Inject
    public TransportSyncApiKeyAction(
        TransportService transportService,
        ActionFilters actionFilters,
        ApiKeyTemplateService apiKeyTemplateService,
        SecurityContext context) {
        super(SyncApiKeyAction.NAME, transportService, actionFilters, SyncApiKeyRequest::new);
        this.apiKeyTemplateService = apiKeyTemplateService;
        this.securityContext = context;
    }

    @Override
    protected void doExecute(Task task, SyncApiKeyRequest request, ActionListener<SyncApiKeyResponse> listener) {
        final Authentication authentication = securityContext.getAuthentication();
        if (authentication == null) {
            listener.onFailure(new IllegalStateException("authentication is required"));
        } else {
            if (authentication.getAuthenticationType() != Authentication.AuthenticationType.API_KEY) {
                listener.onFailure(new IllegalStateException("API key sync is only applicable to API key authentication"));
            } else if (authentication.getMetadata().get(ApiKeyService.API_KEY_TEMPLATE_NAME_KEY) == null) {
                listener.onFailure(new IllegalStateException("API key must be created from a template to be syncable"));
            } else {
                apiKeyTemplateService.syncApiKey(authentication, request, listener);
            }
        }
    }
}
