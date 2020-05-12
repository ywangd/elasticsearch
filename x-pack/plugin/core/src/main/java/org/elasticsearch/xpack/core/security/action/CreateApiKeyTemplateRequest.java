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
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static org.elasticsearch.action.ValidateActions.addValidationError;

public final class CreateApiKeyTemplateRequest extends ActionRequest implements ApiKeyTemplateRequest {
    public static final WriteRequest.RefreshPolicy DEFAULT_REFRESH_POLICY = WriteRequest.RefreshPolicy.WAIT_UNTIL;

    private String name;
    private TimeValue expiration;
    private TimeValue keyExpiration;
    private List<RoleDescriptor> roleDescriptors = Collections.emptyList();
    private WriteRequest.RefreshPolicy refreshPolicy = DEFAULT_REFRESH_POLICY;

    public CreateApiKeyTemplateRequest() {}

    public CreateApiKeyTemplateRequest(@Nullable String name, @Nullable List<RoleDescriptor> roleDescriptors,
        @Nullable TimeValue expiration, @Nullable TimeValue keyExpiration) {
        this.name = name;
        this.roleDescriptors = (roleDescriptors == null) ? List.of() : List.copyOf(roleDescriptors);
        this.expiration = expiration;
        this.keyExpiration = keyExpiration;
    }

    public CreateApiKeyTemplateRequest(StreamInput in) throws IOException {
        super(in);
        this.name = in.readOptionalString();
        this.expiration = in.readOptionalTimeValue();
        this.keyExpiration = in.readOptionalTimeValue();
        this.roleDescriptors = List.copyOf(in.readList(RoleDescriptor::new));
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
        return name;
    }

    public TimeValue getExpiration() {
        return expiration;
    }

    public void setExpiration(@Nullable TimeValue expiration) {
        this.expiration = expiration;
    }

    public TimeValue getKeyExpiration() {
        return keyExpiration;
    }

    public void setKeyExpiration(TimeValue keyExpiration) {
        this.keyExpiration = keyExpiration;
    }

    public List<RoleDescriptor> getRoleDescriptors() {
        return roleDescriptors;
    }

    public void setRoleDescriptors(@Nullable List<RoleDescriptor> roleDescriptors) {
        this.roleDescriptors = (roleDescriptors == null) ? List.of() : List.copyOf(roleDescriptors);
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
        out.writeOptionalString(name);
        out.writeOptionalTimeValue(expiration);
        out.writeOptionalTimeValue(keyExpiration);
        out.writeList(roleDescriptors);
        refreshPolicy.writeTo(out);
    }

    @Override
    public String getAction() {
        return "manage";
    }
}
