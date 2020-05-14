/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.Version;
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
 * Request for invalidating API key(s) so that it can no longer be used
 */
public final class InvalidateApiKeyTemplateRequest extends ActionRequest {

    private final String realmName;
    private final String userName;
    private final String name;
    private final boolean ownedByAuthenticatedUser;

    public InvalidateApiKeyTemplateRequest() {
        this(null, null, null, false);
    }

    public InvalidateApiKeyTemplateRequest(StreamInput in) throws IOException {
        super(in);
        realmName = in.readOptionalString();
        userName = in.readOptionalString();
        name = in.readOptionalString();
        ownedByAuthenticatedUser = in.readOptionalBoolean();
    }

    public InvalidateApiKeyTemplateRequest(@Nullable String realmName, @Nullable String userName,
                                   @Nullable String name, boolean ownedByAuthenticatedUser) {
        this.realmName = realmName;
        this.userName = userName;
        this.name = name;
        this.ownedByAuthenticatedUser = ownedByAuthenticatedUser;
    }

    public String getRealmName() {
        return realmName;
    }

    public String getUserName() {
        return userName;
    }

    public String getName() {
        return name;
    }

    public boolean ownedByAuthenticatedUser() {
        return ownedByAuthenticatedUser;
    }

    /**
     * Creates invalidate api key request for given realm name
     *
     * @param realmName realm name
     * @return {@link InvalidateApiKeyTemplateRequest}
     */
    public static InvalidateApiKeyTemplateRequest usingRealmName(String realmName) {
        return new InvalidateApiKeyTemplateRequest(realmName, null, null, false);
    }

    /**
     * Creates invalidate API key request for given user name
     *
     * @param userName user name
     * @return {@link InvalidateApiKeyTemplateRequest}
     */
    public static InvalidateApiKeyTemplateRequest usingUserName(String userName) {
        return new InvalidateApiKeyTemplateRequest(null, userName, null, false);
    }

    /**
     * Creates invalidate API key request for given realm and user name
     *
     * @param realmName realm name
     * @param userName  user name
     * @return {@link InvalidateApiKeyTemplateRequest}
     */
    public static InvalidateApiKeyTemplateRequest usingRealmAndUserName(String realmName, String userName) {
        return new InvalidateApiKeyTemplateRequest(realmName, userName, null, false);
    }


    /**
     * Creates invalidate api key request for given api key name
     *
     * @param name api key name
     * @param ownedByAuthenticatedUser set {@code true} if the request is only for the API keys owned by current authenticated user else
     * {@code false}
     * @return {@link InvalidateApiKeyTemplateRequest}
     */
    public static InvalidateApiKeyTemplateRequest usingApiKeyTemplateName(String name, boolean ownedByAuthenticatedUser) {
        return new InvalidateApiKeyTemplateRequest(null, null, name, ownedByAuthenticatedUser);
    }

    /**
     * Creates invalidate api key request to invalidate api keys owned by the current authenticated user.
     */
    public static InvalidateApiKeyTemplateRequest forOwnedApiKeyTemplates() {
        return new InvalidateApiKeyTemplateRequest(null, null, null, true);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (Strings.hasText(realmName) == false && Strings.hasText(userName) == false
            && Strings.hasText(name) == false && ownedByAuthenticatedUser == false) {
            validationException = addValidationError("One of [api key id, api key name, username, realm name] must be specified if " +
                "[owner] flag is false", validationException);
        }
        if (ownedByAuthenticatedUser) {
            if (Strings.hasText(realmName) || Strings.hasText(userName)) {
                validationException = addValidationError(
                    "neither username nor realm-name may be specified when invalidating owned API keys",
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
        out.writeOptionalString(name);
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
        InvalidateApiKeyTemplateRequest that = (InvalidateApiKeyTemplateRequest) o;
        return ownedByAuthenticatedUser == that.ownedByAuthenticatedUser &&
            Objects.equals(realmName, that.realmName) &&
            Objects.equals(userName, that.userName) &&
            Objects.equals(name, that.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(realmName, userName, name, ownedByAuthenticatedUser);
    }
}
