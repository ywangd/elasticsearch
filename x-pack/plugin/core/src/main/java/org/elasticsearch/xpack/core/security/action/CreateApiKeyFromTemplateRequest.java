/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.Objects;

import static org.elasticsearch.action.ValidateActions.addValidationError;

public final class CreateApiKeyFromTemplateRequest extends ActionRequest implements ApiKeyTemplateRequest {
    public static final WriteRequest.RefreshPolicy DEFAULT_REFRESH_POLICY = WriteRequest.RefreshPolicy.WAIT_UNTIL;

    private String templateName;
    private String name;
    private WriteRequest.RefreshPolicy refreshPolicy = DEFAULT_REFRESH_POLICY;

    public CreateApiKeyFromTemplateRequest() {}

    public CreateApiKeyFromTemplateRequest(String templateName, @Nullable String name) {
        this.templateName = templateName;
        this.name = name;
    }

    public CreateApiKeyFromTemplateRequest(StreamInput in) throws IOException {
        super(in);
        this.templateName = in.readString();
        this.name = in.readOptionalString();
        this.refreshPolicy = WriteRequest.RefreshPolicy.readFrom(in);
    }

    public String getName() {
        return name;
    }

    public void setName(@Nullable String name) {
        this.name = name;
    }

    @Override
    public String getTemplateName() {
        return templateName;
    }

    public void setTemplateName(String templateName) {
        this.templateName = templateName;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }

    public void setRefreshPolicy(WriteRequest.RefreshPolicy refreshPolicy) {
        this.refreshPolicy = Objects.requireNonNull(refreshPolicy, "refresh policy may not be null");
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (name != null) {
            if (name.length() > 256) {
                validationException = addValidationError("name may not be more than 256 characters long", validationException);
            }
            if (name.equals(name.trim()) == false) {
                validationException = addValidationError("name may not begin or end with whitespace", validationException);
            }
            if (name.startsWith("_")) {
                validationException = addValidationError("name may not begin with an underscore", validationException);
            }
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(templateName);
        out.writeOptionalString(name);
        refreshPolicy.writeTo(out);
    }

    @Override
    public String getAction() {
        return "invoke";
    }
}
