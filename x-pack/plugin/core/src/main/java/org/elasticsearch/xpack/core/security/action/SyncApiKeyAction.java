/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.action.ActionType;

/**
 * ActionType for the creation of an API key
 */
public final class SyncApiKeyAction extends ActionType<SyncApiKeyResponse> {

    public static final String NAME = "cluster:admin/xpack/security/api_key/sync";
    public static final SyncApiKeyAction INSTANCE = new SyncApiKeyAction();

    private SyncApiKeyAction() {
        super(NAME, SyncApiKeyResponse::new);
    }

}
