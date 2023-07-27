/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.action.apikey;

import org.elasticsearch.action.ActionType;

/**
 * ActionType for the creation of a cross-cluster API key
 */
public final class CreateCrossClusterKeyAction extends ActionType<CreateCrossClusterKeyResponse> {

    public static final String NAME = "cluster:admin/xpack/security/cross_cluster_key/create";
    public static final CreateCrossClusterKeyAction INSTANCE = new CreateCrossClusterKeyAction();

    private CreateCrossClusterKeyAction() {
        super(NAME, CreateCrossClusterKeyResponse::new);
    }

}
