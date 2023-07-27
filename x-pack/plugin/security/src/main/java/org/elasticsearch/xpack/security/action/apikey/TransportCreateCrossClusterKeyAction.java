/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.action.apikey;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.core.security.action.apikey.CreateCrossClusterApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.apikey.CreateCrossClusterKeyAction;
import org.elasticsearch.xpack.core.security.action.apikey.CreateCrossClusterKeyResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.security.authc.CrossClusterKeyService;

/**
 * Implementation of the action needed to create an API key
 */
public final class TransportCreateCrossClusterKeyAction extends HandledTransportAction<
    CreateCrossClusterApiKeyRequest,
    CreateCrossClusterKeyResponse> {

    private final CrossClusterKeyService crossClusterKeyService;
    private final SecurityContext securityContext;

    @Inject
    public TransportCreateCrossClusterKeyAction(
        TransportService transportService,
        ActionFilters actionFilters,
        CrossClusterKeyService crossClusterKeyService,
        SecurityContext context
    ) {
        super(CreateCrossClusterKeyAction.NAME, transportService, actionFilters, CreateCrossClusterApiKeyRequest::new);
        this.crossClusterKeyService = crossClusterKeyService;
        this.securityContext = context;
    }

    @Override
    protected void doExecute(Task task, CreateCrossClusterApiKeyRequest request, ActionListener<CreateCrossClusterKeyResponse> listener) {
        final Authentication authentication = securityContext.getAuthentication();
        if (authentication == null) {
            listener.onFailure(new IllegalStateException("authentication is required"));
        } else if (authentication.isApiKey()) {
            listener.onFailure(
                new IllegalArgumentException(
                    "authentication via API key not supported: An API key cannot be used to create a cross-cluster API key"
                )
            );
        } else {
            crossClusterKeyService.createCrossClusterKey(authentication, request, listener);
        }
    }
}
