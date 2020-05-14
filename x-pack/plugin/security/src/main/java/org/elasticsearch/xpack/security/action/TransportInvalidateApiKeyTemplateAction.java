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
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.core.security.action.InvalidateApiKeyTemplateAction;
import org.elasticsearch.xpack.core.security.action.InvalidateApiKeyTemplateRequest;
import org.elasticsearch.xpack.core.security.action.InvalidateApiKeyTemplateResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.security.authc.ApiKeyTemplateService;

public final class TransportInvalidateApiKeyTemplateAction extends HandledTransportAction<InvalidateApiKeyTemplateRequest, InvalidateApiKeyTemplateResponse> {

    private final ApiKeyTemplateService apiKeyTemplateService;
    private final SecurityContext securityContext;

    @Inject
    public TransportInvalidateApiKeyTemplateAction(TransportService transportService, ActionFilters actionFilters,
                            ApiKeyTemplateService apiKeyTemplateService,
                                           SecurityContext context) {
        super(InvalidateApiKeyTemplateAction.NAME, transportService, actionFilters,
            (Writeable.Reader<InvalidateApiKeyTemplateRequest>) InvalidateApiKeyTemplateRequest::new);
        this.apiKeyTemplateService = apiKeyTemplateService;
        this.securityContext = context;
    }

    @Override
    protected void doExecute(Task task, InvalidateApiKeyTemplateRequest request, ActionListener<InvalidateApiKeyTemplateResponse> listener) {
        String apiKeyName = request.getName();
        String username = request.getUserName();
        String realm = request.getRealmName();

        final Authentication authentication = securityContext.getAuthentication();
        if (authentication == null) {
            listener.onFailure(new IllegalStateException("authentication is required"));
        }
        if (request.ownedByAuthenticatedUser()) {
            assert username == null;
            assert realm == null;
            // restrict username and realm to current authenticated user.
            username = authentication.getUser().principal();
            realm = ApiKeyTemplateService.getCreatorRealmName(authentication);
        }

        apiKeyTemplateService.invalidateApiKeyTemplates(realm, username, apiKeyName, listener);
    }

}
