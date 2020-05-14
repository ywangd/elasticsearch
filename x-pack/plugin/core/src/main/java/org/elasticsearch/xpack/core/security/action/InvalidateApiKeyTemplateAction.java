/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.action.ActionType;

/**
 * ActionType for invalidating API key
 */
public final class InvalidateApiKeyTemplateAction extends ActionType<InvalidateApiKeyTemplateResponse> {

    public static final String NAME = "cluster:admin/xpack/security/api_key_template/invalidate";
    public static final InvalidateApiKeyTemplateAction INSTANCE = new InvalidateApiKeyTemplateAction();

    private InvalidateApiKeyTemplateAction() {
        super(NAME, InvalidateApiKeyTemplateResponse::new);
    }
}
