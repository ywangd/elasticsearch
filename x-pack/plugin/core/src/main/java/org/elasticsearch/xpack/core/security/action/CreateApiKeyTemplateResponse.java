/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.CharArrays;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

import static org.elasticsearch.common.xcontent.ConstructingObjectParser.constructorArg;
import static org.elasticsearch.common.xcontent.ConstructingObjectParser.optionalConstructorArg;

/**
 * Response for the successful creation of an api key template
 */
public final class CreateApiKeyTemplateResponse extends ActionResponse implements ToXContentObject {

    static final ConstructingObjectParser<CreateApiKeyTemplateResponse, Void> PARSER = new ConstructingObjectParser<>("create_api_key_template_response",
            args -> new CreateApiKeyTemplateResponse((String) args[0], (String) args[1],
                    (args[2] == null) ? null : Instant.ofEpochMilli((Long) args[2]),
                (Boolean) args[3]));
    static {
        PARSER.declareString(constructorArg(), new ParseField("name"));
        PARSER.declareString(constructorArg(), new ParseField("id"));
        PARSER.declareLong(optionalConstructorArg(), new ParseField("expiration"));
        PARSER.declareBoolean(optionalConstructorArg(), new ParseField("created"));
    }

    private final String name;
    private final String id;
    private final Instant expiration;
    private final boolean created;

    public CreateApiKeyTemplateResponse(String name, String id, Instant expiration, boolean created) {
        this.name = name;
        this.id = id;
        // As we do not yet support the nanosecond precision when we serialize to JSON,
        // here creating the 'Instant' of milliseconds precision.
        // This Instant can then be used for date comparison.
        this.expiration = (expiration != null) ? Instant.ofEpochMilli(expiration.toEpochMilli()): null;
        this.created = created;
    }

    public CreateApiKeyTemplateResponse(StreamInput in) throws IOException {
        super(in);
        this.name = in.readString();
        this.id = in.readString();
        this.expiration = in.readOptionalInstant();
        this.created = in.readBoolean();
    }

    public String getName() {
        return name;
    }

    public String getId() {
        return id;
    }

    @Nullable
    public Instant getExpiration() {
        return expiration;
    }

    public boolean isCreated() {
        return created;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((expiration == null) ? 0 : expiration.hashCode());
        result = prime * result + Objects.hash(id, name, created);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final CreateApiKeyTemplateResponse other = (CreateApiKeyTemplateResponse) obj;
        if (expiration == null) {
            if (other.expiration != null)
                return false;
        } else if (!Objects.equals(expiration, other.expiration))
            return false;
        return Objects.equals(id, other.id)
                && Objects.equals(name, other.name)
            && created == other.created;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeString(id);
        out.writeOptionalInstant(expiration);
        out.writeBoolean(created);
    }

    public static CreateApiKeyTemplateResponse fromXContent(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
            .field("id", id)
            .field("name", name);
        if (expiration != null) {
            builder.field("expiration", expiration.toEpochMilli());
        }
        builder.field("created", created);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "CreateApiKeyTemplateResponse [name=" + name + ", id=" + id + ", expiration=" + expiration
            + ", created=" + created+ "]";
    }

}
