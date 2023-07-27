/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.action.apikey;

import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.core.Assertions;
import org.elasticsearch.xcontent.ToXContentObject;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.elasticsearch.xpack.core.security.action.apikey.CrossClusterApiKeyRoleDescriptorBuilder.CCR_INDICES_PRIVILEGE_NAMES;
import static org.elasticsearch.xpack.core.security.action.apikey.CrossClusterApiKeyRoleDescriptorBuilder.CCS_INDICES_PRIVILEGE_NAMES;

// TODO: temporary, to be removed.
public record CrossClusterKey(String name, String id, List<RoleDescriptor> roleDescriptors) implements ToXContentObject, Writeable {

    public CrossClusterKey(StreamInput in) throws IOException {
        this(in.readString(), in.readString(), in.readList(RoleDescriptor::new));
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("id", id).field("name", name);
        buildXContentForCrossClusterApiKeyAccess(builder, roleDescriptors.iterator().next());
        return builder.endObject();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeString(id);
        out.writeOptionalCollection(roleDescriptors);
    }

    private void buildXContentForCrossClusterApiKeyAccess(XContentBuilder builder, RoleDescriptor roleDescriptor) throws IOException {
        if (Assertions.ENABLED) {
            CrossClusterApiKeyRoleDescriptorBuilder.validate(roleDescriptor);
        }
        final List<RoleDescriptor.IndicesPrivileges> search = new ArrayList<>();
        final List<RoleDescriptor.IndicesPrivileges> replication = new ArrayList<>();
        for (RoleDescriptor.IndicesPrivileges indicesPrivileges : roleDescriptor.getIndicesPrivileges()) {
            if (Arrays.equals(CCS_INDICES_PRIVILEGE_NAMES, indicesPrivileges.getPrivileges())) {
                search.add(indicesPrivileges);
            } else {
                assert Arrays.equals(CCR_INDICES_PRIVILEGE_NAMES, indicesPrivileges.getPrivileges());
                replication.add(indicesPrivileges);
            }
        }
        builder.startObject("access");
        final Params params = new MapParams(Map.of("_with_privileges", "false"));
        if (false == search.isEmpty()) {
            builder.startArray("search");
            for (RoleDescriptor.IndicesPrivileges indicesPrivileges : search) {
                indicesPrivileges.toXContent(builder, params);
            }
            builder.endArray();
        }
        if (false == replication.isEmpty()) {
            builder.startArray("replication");
            for (RoleDescriptor.IndicesPrivileges indicesPrivileges : replication) {
                indicesPrivileges.toXContent(builder, params);
            }
            builder.endArray();
        }
        builder.endObject();
    }
}
