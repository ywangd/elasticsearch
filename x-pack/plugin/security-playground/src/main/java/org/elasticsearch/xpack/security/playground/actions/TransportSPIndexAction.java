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
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;

public class TransportSPIndexAction extends HandledTransportAction<SPIndexAction.Request, SPIndexAction.Response> {

    @Inject
    public TransportSPIndexAction(TransportService transportService, ActionFilters actionFilters) {
        super(SPIndexAction.NAME, transportService, actionFilters, SPIndexAction.Request::new);
    }

    @Override
    protected void doExecute(Task task, SPIndexAction.Request request, ActionListener<SPIndexAction.Response> listener) {
        listener.onResponse(new SPIndexAction.Response(request.indices()));
    }

}
