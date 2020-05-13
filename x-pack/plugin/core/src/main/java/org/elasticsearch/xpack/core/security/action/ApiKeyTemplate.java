/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;

import java.io.IOException;
import java.time.Instant;
import java.util.Objects;

import static org.elasticsearch.common.xcontent.ConstructingObjectParser.constructorArg;
import static org.elasticsearch.common.xcontent.ConstructingObjectParser.optionalConstructorArg;

/**
 * API key information
 */
public final class ApiKeyTemplate implements ToXContentObject, Writeable {

    private final String name;
    private final Instant creation;
    private final Instant expiration;
    private final boolean invalidated;
    private final String username;
    private final String realm;

    public ApiKeyTemplate(
        String name, Instant creation, Instant expiration, boolean invalidated, String username, String realm) {
        this.name = name;
        // As we do not yet support the nanosecond precision when we serialize to JSON,
        // here creating the 'Instant' of milliseconds precision.
        // This Instant can then be used for date comparison.
        this.creation = Instant.ofEpochMilli(creation.toEpochMilli());
        this.expiration = (expiration != null) ? Instant.ofEpochMilli(expiration.toEpochMilli()): null;
        this.invalidated = invalidated;
        this.username = username;
        this.realm = realm;
    }

    public ApiKeyTemplate(StreamInput in) throws IOException {
        this.name = in.readString();
        this.creation = in.readInstant();
        this.expiration = in.readOptionalInstant();
        this.invalidated = in.readBoolean();
        this.username = in.readString();
        this.realm = in.readString();
    }

    public String getName() {
        return name;
    }

    public Instant getCreation() {
        return creation;
    }

    public Instant getExpiration() {
        return expiration;
    }

    public boolean isInvalidated() {
        return invalidated;
    }

    public String getUsername() {
        return username;
    }

    public String getRealm() {
        return realm;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
        .field("name", name)
        .field("creation", creation.toEpochMilli());
        if (expiration != null) {
            builder.field("expiration", expiration.toEpochMilli());
        }
        builder.field("invalidated", invalidated)
        .field("username", username)
        .field("realm", realm);
        return builder.endObject();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeInstant(creation);
        out.writeOptionalInstant(expiration);
        out.writeBoolean(invalidated);
        out.writeString(username);
        out.writeString(realm);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, creation, expiration, invalidated, username, realm);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        ApiKeyTemplate other = (ApiKeyTemplate) obj;
        return Objects.equals(name, other.name)
                && Objects.equals(creation, other.creation)
                && Objects.equals(expiration, other.expiration)
                && Objects.equals(invalidated, other.invalidated)
                && Objects.equals(username, other.username)
                && Objects.equals(realm, other.realm);
    }

    static final ConstructingObjectParser<ApiKeyTemplate, Void> PARSER = new ConstructingObjectParser<>("api_key", args -> {
        return new ApiKeyTemplate((String) args[0], Instant.ofEpochMilli((Long) args[1]),
                (args[2] == null) ? null : Instant.ofEpochMilli((Long) args[2]), (Boolean) args[3], (String) args[4], (String) args[5]);
    });
    static {
        PARSER.declareString(constructorArg(), new ParseField("name"));
        PARSER.declareLong(constructorArg(), new ParseField("creation"));
        PARSER.declareLong(optionalConstructorArg(), new ParseField("expiration"));
        PARSER.declareBoolean(constructorArg(), new ParseField("invalidated"));
        PARSER.declareString(constructorArg(), new ParseField("username"));
        PARSER.declareString(constructorArg(), new ParseField("realm"));
    }

    public static ApiKeyTemplate fromXContent(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }

    @Override
    public String toString() {
        return "ApiKeyTemplate [name=" + name + ", creation=" + creation + ", expiration=" + expiration + ", invalidated="
                + invalidated + ", username=" + username + ", realm=" + realm + "]";
    }

}
