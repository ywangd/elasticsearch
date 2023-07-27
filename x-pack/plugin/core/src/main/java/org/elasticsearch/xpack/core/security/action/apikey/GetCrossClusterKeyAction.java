/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.action.apikey;

import org.elasticsearch.action.ActionType;

/**
 * ActionType for retrieving cross cluster key(s)
 */
public final class GetCrossClusterKeyAction extends ActionType<GetCrossClusterKeyResponse> {

    public static final String NAME = "cluster:admin/xpack/security/cross_cluster_key/get";
    public static final GetCrossClusterKeyAction INSTANCE = new GetCrossClusterKeyAction();

    private GetCrossClusterKeyAction() {
        super(NAME, GetCrossClusterKeyResponse::new);
    }
}
