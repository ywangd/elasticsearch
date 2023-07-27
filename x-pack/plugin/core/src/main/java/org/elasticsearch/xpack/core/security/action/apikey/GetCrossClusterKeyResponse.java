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
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.xcontent.ToXContentObject;
import org.elasticsearch.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

/**
 * Response for get API keys.<br>
 * The result contains information about the API keys that were found.
 */
public final class GetCrossClusterKeyResponse extends ActionResponse implements ToXContentObject, Writeable {

    private final CrossClusterKey[] foundCrossClusterKeysInfo;

    public GetCrossClusterKeyResponse(StreamInput in) throws IOException {
        super(in);
        this.foundCrossClusterKeysInfo = in.readArray(CrossClusterKey::new, CrossClusterKey[]::new);
    }

    public GetCrossClusterKeyResponse(Collection<CrossClusterKey> foundCrossClusterKeysInfo) {
        Objects.requireNonNull(foundCrossClusterKeysInfo, "found_cross_cluster_keys_info must be provided");
        this.foundCrossClusterKeysInfo = foundCrossClusterKeysInfo.toArray(new CrossClusterKey[0]);
    }

    public static GetCrossClusterKeyResponse emptyResponse() {
        return new GetCrossClusterKeyResponse(Collections.emptyList());
    }

    public CrossClusterKey[] getCrossClusterKeysInfo() {
        return foundCrossClusterKeysInfo;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject().array("cross_cluster_keys", (Object[]) foundCrossClusterKeysInfo);
        return builder.endObject();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeArray(foundCrossClusterKeysInfo);
    }

    @Override
    public String toString() {
        return "GetCrossClusterKeyResponse [foundCrossClusterKeysInfo=" + foundCrossClusterKeysInfo + "]";
    }

}
