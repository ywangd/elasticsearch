/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.action.apikey;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.core.CharArrays;
import org.elasticsearch.xcontent.ToXContentObject;
import org.elasticsearch.xcontent.XContentBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Response for the successful creation of an api key
 */
public final class CreateCrossClusterKeyResponse extends ActionResponse implements ToXContentObject {
    private final String name;
    private final String id;
    private final SecureString key;

    public CreateCrossClusterKeyResponse(String name, String id, SecureString key) {
        this.name = name;
        this.id = id;
        this.key = key;
    }

    public CreateCrossClusterKeyResponse(StreamInput in) throws IOException {
        super(in);
        this.name = in.readString();
        this.id = in.readString();
        byte[] bytes = null;
        try {
            bytes = in.readByteArray();
            this.key = new SecureString(CharArrays.utf8BytesToChars(bytes));
        } finally {
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
            }
        }
    }

    public String getName() {
        return name;
    }

    public String getId() {
        return id;
    }

    public SecureString getKey() {
        return key;
    }

    public String getEncoded() {
        return "cc_" + Base64.getEncoder().encodeToString((id + ":" + key).getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Objects.hash(id, name, key);
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
        final CreateCrossClusterKeyResponse other = (CreateCrossClusterKeyResponse) obj;
        return Objects.equals(id, other.id) && Objects.equals(key, other.key) && Objects.equals(name, other.name);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeString(id);
        byte[] bytes = null;
        try {
            bytes = CharArrays.toUtf8Bytes(key.getChars());
            out.writeByteArray(bytes);
        } finally {
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
            }
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject().field("id", id).field("name", name);
        builder.field("encoded", getEncoded());
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "CreateApiKeyResponse [name=" + name + ", id=" + id + "]";
    }

}
