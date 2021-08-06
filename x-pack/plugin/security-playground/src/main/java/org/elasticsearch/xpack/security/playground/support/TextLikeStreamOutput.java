/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.support;

import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.settings.SecureString;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;

public class TextLikeStreamOutput extends BytesStreamOutput {

    @Override
    public void writeOptionalString(String str) throws IOException {
        if (str != null) {
            super.writeBytes(str.getBytes(StandardCharsets.UTF_8));
        }
    }

    @Override
    public void writeOptionalSecureString(SecureString secureStr) throws IOException {
        if (secureStr != null) {
            super.writeBytes(secureStr.toString().getBytes(StandardCharsets.UTF_8));
        }
    }

    @Override
    public void writeStringArray(String[] array) throws IOException {
        for (String str : array) {
            writeOptionalString(str);
            super.writeByte((byte) ' ');
        }
    }

    @Override
    public void writeStringArrayNullable(String[] array) throws IOException {
        if (array != null) {
            writeStringArray(array);
        }
    }

    @Override
    public void writeOptionalStringArray(String[] array) throws IOException {
        writeStringArrayNullable(array);
    }

    @Override
    public void writeStringCollection(Collection<String> collection) throws IOException {
        writeStringArray(collection.toArray(String[]::new));
    }

    @Override
    public void writeOptionalStringCollection(Collection<String> collection) throws IOException {
        if (collection != null) {
            writeStringCollection(collection);
        }
    }

    @Override
    public String toString() {
        return new String(bytes().toBytesRef().bytes, StandardCharsets.US_ASCII).replaceAll("[^\\p{Print}]", "?");
    }
}
