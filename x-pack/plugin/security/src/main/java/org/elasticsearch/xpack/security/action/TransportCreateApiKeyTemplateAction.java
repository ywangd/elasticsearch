/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.action;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.common.IteratingActionListener;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyTemplateAction;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyTemplateRequest;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyTemplateResponse;
import org.elasticsearch.xpack.core.security.action.user.HasPrivilegesRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor.IndicesPrivileges;
import org.elasticsearch.xpack.security.authc.ApiKeyTemplateService;
import org.elasticsearch.xpack.security.authc.support.ApiKeyTemplateGenerator;
import org.elasticsearch.xpack.security.authz.AuthorizationService;
import org.elasticsearch.xpack.security.authz.store.CompositeRolesStore;
import org.elasticsearch.xpack.security.authz.store.NativePrivilegeStore;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Implementation of the action needed to create an API key
 */
public final class TransportCreateApiKeyTemplateAction
    extends HandledTransportAction<CreateApiKeyTemplateRequest, CreateApiKeyTemplateResponse> {

    private final ApiKeyTemplateGenerator generator;
    private final SecurityContext securityContext;
    private final AuthorizationService authorizationService;
    private final NativePrivilegeStore privilegeStore;

    @Inject
    public TransportCreateApiKeyTemplateAction(
        TransportService transportService,
        ActionFilters actionFilters,
        ApiKeyTemplateService apiKeyTemplateService,
        SecurityContext context,
        CompositeRolesStore rolesStore,
        AuthorizationService authorizationService,
        NativePrivilegeStore privilegeStore,
        NamedXContentRegistry xContentRegistry) {
        super(CreateApiKeyTemplateAction.NAME, transportService, actionFilters, CreateApiKeyTemplateRequest::new);
        this.authorizationService = authorizationService;
        this.privilegeStore = privilegeStore;
        this.generator = new ApiKeyTemplateGenerator(apiKeyTemplateService, rolesStore, xContentRegistry);
        this.securityContext = context;
    }

    @Override
    protected void doExecute(Task task, CreateApiKeyTemplateRequest request, ActionListener<CreateApiKeyTemplateResponse> listener) {
        final Authentication authentication = securityContext.getAuthentication();
        if (authentication == null) {
            listener.onFailure(new IllegalStateException("authentication is required"));
        } else {

            final IteratingActionListener<Void, RoleDescriptor> iteratingActionListener =
                new IteratingActionListener<>(ActionListener.wrap(r -> {
                    generator.generateApiKeyTemplate(authentication, request, listener);
                }, listener::onFailure), this::checkRoleDescriptor, request.getRoleDescriptors(), securityContext.getThreadContext());
            iteratingActionListener.run();
        }
    }

    // TODO: this does not currently check global privileges, DLS or FLS
    private void checkRoleDescriptor(RoleDescriptor roleDescriptor, ActionListener<Void> listener) {
        final Authentication authentication = securityContext.getAuthentication();
        final IndicesPrivileges[] indicesPrivileges = roleDescriptor.getIndicesPrivileges();
        if (indicesPrivileges != null) {
            if (Arrays.stream(indicesPrivileges).anyMatch(p -> p.isUsingDocumentLevelSecurity() || p.isUsingFieldLevelSecurity())) {
                listener.onFailure(new IllegalArgumentException("users with DLS/FLS privilege cannot create API key template"));
                return;
            }
        }

        final Set<String> applicationNames = Arrays.stream(roleDescriptor.getApplicationPrivileges())
            .map(RoleDescriptor.ApplicationResourcePrivileges::getApplication)
            .collect(Collectors.toSet());

        final HasPrivilegesRequest hasPrivilegesRequest = new HasPrivilegesRequest();
        hasPrivilegesRequest.clusterPrivileges(roleDescriptor.getClusterPrivileges());
        hasPrivilegesRequest.indexPrivileges(roleDescriptor.getIndicesPrivileges());
        hasPrivilegesRequest.applicationPrivileges(roleDescriptor.getApplicationPrivileges());
        hasPrivilegesRequest.username(authentication.getUser().principal());

        privilegeStore.getPrivileges(applicationNames, null,
            ActionListener.wrap(applicationPrivilegeDescriptors -> authorizationService.checkPrivileges(
                authentication, hasPrivilegesRequest, applicationPrivilegeDescriptors, ActionListener.wrap(hasPrivilegesResponse -> {
                        if (hasPrivilegesResponse.isCompleteMatch()) {
                            listener.onResponse(null);
                        } else {
                            listener.onFailure(new IllegalArgumentException(hasPrivilegesResponse.toString()));
                        }
                    },
                    listener::onFailure)),
                listener::onFailure));
    }
}
