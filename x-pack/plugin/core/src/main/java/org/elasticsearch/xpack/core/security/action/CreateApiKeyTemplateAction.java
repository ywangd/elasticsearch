/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.action.ActionType;

/**
 * ActionType for the creation of an API key template
 */
public final class CreateApiKeyTemplateAction extends ActionType<CreateApiKeyTemplateResponse> {

    public static final String NAME = "cluster:admin/xpack/security/api_key_template/create";
    public static final CreateApiKeyTemplateAction INSTANCE = new CreateApiKeyTemplateAction();

    private CreateApiKeyTemplateAction() {
        super(NAME, CreateApiKeyTemplateResponse::new);
    }

}
