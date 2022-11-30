/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security;

import org.elasticsearch.action.update.DefaultUpdateHelper;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.index.get.GetResult;
import org.elasticsearch.index.shard.IndexShard;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.core.security.authz.AuthorizationServiceField;
import org.elasticsearch.xpack.core.security.authz.accesscontrol.IndicesAccessControl;
import org.elasticsearch.xpack.core.security.support.Exceptions;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Map;

public class SecurityDefaultUpdateHelper extends DefaultUpdateHelper {

    private final SecurityContext securityContext;

    public SecurityDefaultUpdateHelper(ScriptService scriptService, SecurityContext securityContext) {
        super(scriptService);
        this.securityContext = securityContext;
    }

    @Override
    protected Map<String, Object> validateAndTransform(
        Map<String, Object> source,
        IndexShard indexShard,
        String id,
        long primaryTerm,
        long seqNo
    ) {
        final ThreadContext threadContext = securityContext.getThreadContext();
        IndicesAccessControl indicesAccessControl = threadContext.getTransient(AuthorizationServiceField.INDICES_PERMISSIONS_KEY);
        if (indicesAccessControl == null) {
            throw Exceptions.authorizationError("no indices permissions found");
        }
        final IndicesAccessControl.IndexAccessControl indexAccessControl = indicesAccessControl.getIndexPermissions(
            indexShard.shardId().getIndexName()
        );
        indexAccessControl.getFieldPermissions().validate(source);

        final GetResult getResult;
        try (var ignored = threadContext.stashContext()) {
            threadContext.putTransient(AuthorizationServiceField.INDICES_PERMISSIONS_KEY, IndicesAccessControl.allowAll());
            getResult = indexShard.getService().getForUpdate(id, seqNo, primaryTerm);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        final Map<String, Object> updatedSource = XContentHelper.convertToMap(getResult.internalSourceRef(), true).v2();
        XContentHelper.update(updatedSource, source, false);
        return updatedSource;
    }
}
