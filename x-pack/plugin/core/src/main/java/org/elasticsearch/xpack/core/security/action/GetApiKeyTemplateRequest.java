/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.Objects;

import static org.elasticsearch.action.ValidateActions.addValidationError;

/**
 * Request for get API key
 */
public final class GetApiKeyTemplateRequest extends ActionRequest {

    private final String realmName;
    private final String userName;
    private final String apiKeyTemplateName;
    private final boolean ownedByAuthenticatedUser;

    public GetApiKeyTemplateRequest() {
        this(null, null, null, false);
    }

    public GetApiKeyTemplateRequest(StreamInput in) throws IOException {
        super(in);
        realmName = in.readOptionalString();
        userName = in.readOptionalString();
        apiKeyTemplateName = in.readOptionalString();
        ownedByAuthenticatedUser = in.readOptionalBoolean() != null;
    }

    public GetApiKeyTemplateRequest(@Nullable String realmName, @Nullable String userName,
                            @Nullable String apiKeyTemplateName, boolean ownedByAuthenticatedUser) {
        this.realmName = realmName;
        this.userName = userName;
        this.apiKeyTemplateName = apiKeyTemplateName;
        this.ownedByAuthenticatedUser = ownedByAuthenticatedUser;
    }

    public String getRealmName() {
        return realmName;
    }

    public String getUserName() {
        return userName;
    }

    public String getApiKeyTemplateName() {
        return apiKeyTemplateName;
    }

    public boolean ownedByAuthenticatedUser() {
        return ownedByAuthenticatedUser;
    }

    /**
     * Creates get API key request for given realm name
     * @param realmName realm name
     * @return {@link GetApiKeyTemplateRequest}
     */
    public static GetApiKeyTemplateRequest usingRealmName(String realmName) {
        return new GetApiKeyTemplateRequest(realmName, null, null, false);
    }

    /**
     * Creates get API key request for given user name
     * @param userName user name
     * @return {@link GetApiKeyTemplateRequest}
     */
    public static GetApiKeyTemplateRequest usingUserName(String userName) {
        return new GetApiKeyTemplateRequest(null, userName, null, false);
    }

    /**
     * Creates get API key request for given realm and user name
     * @param realmName realm name
     * @param userName user name
     * @return {@link GetApiKeyTemplateRequest}
     */
    public static GetApiKeyTemplateRequest usingRealmAndUserName(String realmName, String userName) {
        return new GetApiKeyTemplateRequest(realmName, userName, null, false);
    }

    /**
     * Creates get api key request for given api key name
     * @param apiKeyTemplateName api key name
     * @param ownedByAuthenticatedUser set {@code true} if the request is only for the API keys owned by current authenticated user else
     * {@code false}
     * @return {@link GetApiKeyTemplateRequest}
     */
    public static GetApiKeyTemplateRequest usingApiKeyName(String apiKeyTemplateName, boolean ownedByAuthenticatedUser) {
        return new GetApiKeyTemplateRequest(null, null, apiKeyTemplateName, ownedByAuthenticatedUser);
    }

    /**
     * Creates get api key request to retrieve api key information for the api keys owned by the current authenticated user.
     */
    public static GetApiKeyTemplateRequest forOwnedApiKeys() {
        return new GetApiKeyTemplateRequest(null, null, null, true);
    }

    /**
     * Creates get api key request to retrieve api key information for all api keys if the authenticated user is authorized to do so.
     */
    public static GetApiKeyTemplateRequest forAllApiKeys() {
        return new GetApiKeyTemplateRequest();
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (ownedByAuthenticatedUser) {
            if (Strings.hasText(realmName) || Strings.hasText(userName)) {
                validationException = addValidationError(
                    "neither username nor realm-name may be specified when retrieving owned API keys",
                    validationException);
            }
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalString(realmName);
        out.writeOptionalString(userName);
        out.writeOptionalString(apiKeyTemplateName);
        out.writeOptionalBoolean(ownedByAuthenticatedUser);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        GetApiKeyTemplateRequest that = (GetApiKeyTemplateRequest) o;
        return ownedByAuthenticatedUser == that.ownedByAuthenticatedUser &&
            Objects.equals(realmName, that.realmName) &&
            Objects.equals(userName, that.userName) &&
            Objects.equals(apiKeyTemplateName, that.apiKeyTemplateName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(realmName, userName, apiKeyTemplateName, ownedByAuthenticatedUser);
    }
}
