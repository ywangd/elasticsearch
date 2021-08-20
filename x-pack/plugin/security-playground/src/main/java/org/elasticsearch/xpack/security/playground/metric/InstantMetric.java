/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.metric;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;

import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class InstantMetric implements Writeable, ToXContentObject {
    final String nodeName;
    final String xOpaqueId;
    final Map<String, InstantMetricMember> members;

    public InstantMetric(String nodeName, String xOpaqueId) {
        this.nodeName = nodeName;
        this.xOpaqueId = xOpaqueId;
        members = new ConcurrentHashMap<>();
    }

    public InstantMetric(StreamInput in) throws IOException {
        this.nodeName = in.readString();
        this.xOpaqueId = in.readString();
        this.members = new ConcurrentHashMap<>(in.readMap(StreamInput::readString, InstantMetricMember::new));
    }

    InstantMetricMember getOrCreateMember(String action, int requestHash, int authorizationIndex, long startTime) {
        final String key = action + "@" + requestHash + "@" + authorizationIndex;
        return members.computeIfAbsent(key, k -> new InstantMetricMember(startTime, action, requestHash, authorizationIndex));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(nodeName);
        out.writeString(xOpaqueId);
        out.writeMap(members, StreamOutput::writeString, (o, m) -> m.writeTo(o));
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("node_name", nodeName);
        innerToXContent(builder, params);
        builder.endObject();
        return builder;
    }

    public XContentBuilder innerToXContent(XContentBuilder builder, Params params) throws IOException {
        builder.field("x_opaque_id", xOpaqueId);
        final List<Map.Entry<String, InstantMetricMember>> entries = members.entrySet()
            .stream()
            .sorted(Comparator.comparingLong(entry -> entry.getValue().startTime))
            .collect(Collectors.toUnmodifiableList());
        builder.field("number_of_requests", entries.size());
        builder.startArray("requests");
        for (Map.Entry<String, InstantMetricMember> entry : entries) {
            final InstantMetricMember member = entry.getValue();
            builder.startObject()
                .field("action", member.action)
                .field("request_hash", member.requestHash)
                .field("start_time", member.startTime)
                .field("index", member.authorizationIndex)
                .field("username", member.username)
                .field("metric")
                .startObject();
            if (member.resolveAuthorizationInfoElapsed != 0) {
                builder.field(InstrumentedMethod.RESOLVE_AUTHORIZATION_INFO.jsonName(), member.resolveAuthorizationInfoElapsed);
            }
            if (member.authorizeRunAsElapsed != 0) {
                builder.field(InstrumentedMethod.AUTHORIZE_RUN_AS.jsonName(), member.authorizeRunAsElapsed);
            }
            if (member.authorizeClusterActionElapsed != 0) {
                builder.field(InstrumentedMethod.AUTHORIZE_CLUSTER_ACTION.jsonName(), member.authorizeClusterActionElapsed);
            }
            if (member.authorizeIndexActionElapsed != 0) {
                builder.field(InstrumentedMethod.AUTHORIZE_INDEX_ACTION.jsonName(), member.authorizeIndexActionElapsed);
            }
            if (member.loadAuthorizedIndicesElapsed != 0) {
                builder.field(InstrumentedMethod.LOAD_AUTHORIZED_INDICES.jsonName(), member.loadAuthorizedIndicesElapsed);
            }
            if (member.roleAllowedIndicesMatcherElapsed != 0) {
                builder.field(InstrumentedMethod.ROLE_ALLOWED_INDICES_MATCHER.jsonName(), member.roleAllowedIndicesMatcherElapsed);
            }
            if (member.roleAllowedActionsMatcherElapsed != 0) {
                builder.field(InstrumentedMethod.ROLE_ALLOWED_ACTIONS_MATCHER.jsonName(), member.roleAllowedActionsMatcherElapsed);
            }
            if (member.roleCheckRunAsElapsed != 0) {
                builder.field(InstrumentedMethod.ROLE_CHECK_RUN_AS.jsonName(), member.roleCheckRunAsElapsed);
            }
            if (member.roleCheckIndicesActionElapsed != 0) {
                builder.field(InstrumentedMethod.ROLE_CHECK_INDICES_ACTION.jsonName(), member.roleCheckIndicesActionElapsed);
            }
            if (member.roleCheckClusterActionElapsed != 0) {
                builder.field(InstrumentedMethod.ROLE_CHECK_CLUSTER_ACTION.jsonName(), member.roleCheckClusterActionElapsed);
            }
            if (member.roleAuthorizeElapsed != 0) {
                builder.field(InstrumentedMethod.ROLE_AUTHORIZE.jsonName(), member.roleAuthorizeElapsed);
            }
            if (member.iaarResolveElapsed != 0) {
                builder.field("iaar_resolve", member.iaarResolveElapsed);
            }
            builder.endObject().endObject();
        }
        builder.endArray();
        return builder;
    }

    @Override
    public String toString() {
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            toXContent(builder, EMPTY_PARAMS);
            return Strings.toString(builder);
        } catch (Exception e) {
            throw new ElasticsearchException("Failed to build xcontent", e);
        }
    }

    public static class InstantMetricMember implements Writeable {
        final long startTime;
        final String action;
        final int requestHash;
        final int authorizationIndex;
        String username;
        long resolveAuthorizationInfoElapsed;
        long authorizeRunAsElapsed;
        long authorizeClusterActionElapsed;
        long authorizeIndexActionElapsed;
        long loadAuthorizedIndicesElapsed;
        long roleAllowedIndicesMatcherElapsed;
        long roleAllowedActionsMatcherElapsed;
        long roleCheckRunAsElapsed;
        long roleCheckIndicesActionElapsed;
        long roleCheckClusterActionElapsed;
        long roleAuthorizeElapsed;
        long iaarResolveElapsed;

        public InstantMetricMember(long startTime, String action, int requestHash, int authorizationIndex) {
            this.startTime = startTime;
            this.action = action;
            this.requestHash = requestHash;
            this.authorizationIndex = authorizationIndex;
        }

        public InstantMetricMember(StreamInput in) throws IOException {
            this.startTime = in.readLong();
            this.action = in.readString();
            this.requestHash = in.readVInt();
            this.authorizationIndex = in.readVInt();
            this.username = in.readString();
            this.resolveAuthorizationInfoElapsed = in.readLong();
            this.authorizeRunAsElapsed = in.readLong();
            this.authorizeClusterActionElapsed = in.readLong();
            this.authorizeIndexActionElapsed = in.readLong();
            this.loadAuthorizedIndicesElapsed = in.readLong();
            this.roleAllowedIndicesMatcherElapsed = in.readLong();
            this.roleAllowedActionsMatcherElapsed = in.readLong();
            this.roleCheckRunAsElapsed = in.readLong();
            this.roleCheckIndicesActionElapsed = in.readLong();
            this.roleCheckClusterActionElapsed = in.readLong();
            this.roleAuthorizeElapsed = in.readLong();
            this.iaarResolveElapsed = in.readLong();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeLong(startTime);
            out.writeString(action);
            out.writeVInt(requestHash);
            out.writeVInt(authorizationIndex);
            out.writeString(username);
            out.writeLong(resolveAuthorizationInfoElapsed);
            out.writeLong(authorizeRunAsElapsed);
            out.writeLong(authorizeClusterActionElapsed);
            out.writeLong(authorizeIndexActionElapsed);
            out.writeLong(loadAuthorizedIndicesElapsed);
            out.writeLong(roleAllowedIndicesMatcherElapsed);
            out.writeLong(roleAllowedActionsMatcherElapsed);
            out.writeLong(roleCheckRunAsElapsed);
            out.writeLong(roleCheckIndicesActionElapsed);
            out.writeLong(roleCheckClusterActionElapsed);
            out.writeLong(roleAuthorizeElapsed);
            out.writeLong(iaarResolveElapsed);
        }
    }
}
