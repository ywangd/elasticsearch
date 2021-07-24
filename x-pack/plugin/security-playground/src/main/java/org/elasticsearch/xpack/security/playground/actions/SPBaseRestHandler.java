/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.actions;

import org.elasticsearch.common.UUIDs;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.xpack.security.rest.action.SecurityBaseRestHandler;

import java.util.Locale;

public abstract class SPBaseRestHandler extends SecurityBaseRestHandler {

    /**
     * @param settings the node's settings
     * @param licenseState the license state that will be used to determine if security is licensed
     */
    protected SPBaseRestHandler(Settings settings, XPackLicenseState licenseState) {
        super(settings, licenseState);
    }

    protected String generateTraceParent() {
        // 55 char long
        return String.format(Locale.ROOT, "000%s%s", generateTraceId(), UUIDs.base64UUID());
    }

    protected String generateTraceId() {
        // 32 char long
        final String uuid = UUIDs.base64UUID();
        return String.format(Locale.ROOT, "%s%s", uuid, uuid.substring(0, 12));
    }
}
