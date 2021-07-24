/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.actions;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.node.NodeService;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.security.authz.AuthorizationService;
import org.elasticsearch.xpack.security.authz.store.CompositeRolesStore;
import org.elasticsearch.xpack.security.playground.simulation.FileIndicesStatusProvider;

public class TransportSPClusterAction extends HandledTransportAction<SPClusterAction.Request, SPClusterAction.Response> {

    public static CompositeRolesStore compositeRolesStore;
    public static NodeService nodeService;
    public static AuthorizationService authorizationService;
    public static FileIndicesStatusProvider fileIndexAbstractionsProvider;

    @Inject
    public TransportSPClusterAction(
        TransportService transportService,
        ActionFilters actionFilters,
        CompositeRolesStore compositeRolesStore,
        NodeService nodeService,
        AuthorizationService authorizationService,
        FileIndicesStatusProvider fileIndexAbstractionsProvider
    ) {
        super(SPClusterAction.NAME, transportService, actionFilters, in -> SPClusterAction.Request.INSTANCE);
        TransportSPClusterAction.compositeRolesStore = compositeRolesStore;
        TransportSPClusterAction.nodeService = nodeService;
        TransportSPClusterAction.authorizationService = authorizationService;
        TransportSPClusterAction.fileIndexAbstractionsProvider = fileIndexAbstractionsProvider;
    }

    @Override
    protected void doExecute(Task task, SPClusterAction.Request request, ActionListener<SPClusterAction.Response> listener) {
        listener.onResponse(SPClusterAction.Response.INSTANCE);
    }
}
