/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.action.service;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.action.RestActions;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toUnmodifiableList;

public class GetServiceAccountCredentialsResponse extends ActionResponse implements ToXContentObject {

    private final String principal;
    private final List<TokenInfo> indexTokenInfos;
    private final GetServiceAccountFileTokensResponse fileTokensResponse;

    public GetServiceAccountCredentialsResponse(String principal, Collection<TokenInfo> indexTokenInfos,
                                                GetServiceAccountFileTokensResponse fileTokensResponse) {
        this.principal = principal;
        this.indexTokenInfos = indexTokenInfos == null ? List.of() : indexTokenInfos.stream().sorted().collect(toUnmodifiableList());
        this.fileTokensResponse = fileTokensResponse;
    }

    public GetServiceAccountCredentialsResponse(StreamInput in) throws IOException {
        super(in);
        this.principal = in.readString();
        this.indexTokenInfos = in.readList(TokenInfo::new);
        this.fileTokensResponse = new GetServiceAccountFileTokensResponse(in);
    }

    public String getPrincipal() {
        return principal;
    }

    public List<TokenInfo> getIndexTokenInfos() {
        return indexTokenInfos;
    }

    public GetServiceAccountFileTokensResponse getFileTokensResponse() {
        return fileTokensResponse;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(principal);
        out.writeList(indexTokenInfos);
        fileTokensResponse.writeTo(out);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        final List<TokenInfo> fileTokenInfos = fileTokensResponse.getTokenInfos();

        builder.startObject()
            .field("service_account", principal)
            .field("count", indexTokenInfos.size() + fileTokenInfos.size())
            .field("tokens").startObject();
        for (TokenInfo info : indexTokenInfos) {
            info.toXContent(builder, params);
        }
        builder.endObject().field("file_tokens").startObject();
        RestActions.buildNodesHeader(builder, params, fileTokensResponse);
        for (TokenInfo info : fileTokenInfos) {
            info.toXContent(builder, params);
        }
        builder.endObject().endObject();
        return builder;
    }

    @Override
    public String toString() {
        return "GetServiceAccountCredentialsResponse{" + "principal='"
            + principal + '\'' + ", indexTokenInfos=" + indexTokenInfos
            + ", fileTokensResponse=" + fileTokensResponse + '}';
    }
}
