/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.restriction;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.env.Environment;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.XPackPlugin;
import org.elasticsearch.xpack.core.security.authc.Authentication;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

public class RestrictionChecker {

    private static final Logger logger = LogManager.getLogger(RestrictionChecker.class);

    // TODO: enabled setting?
    private final XPackLicenseState licenseState;
    private final ThreadContext threadContext;
    private final Restriction restriction;

    public RestrictionChecker(
        Environment environment, XPackLicenseState licenseState, ThreadContext threadContext) throws IOException {
        this.licenseState = licenseState;
        this.threadContext = threadContext;
        final Path restrictionConfigFilePath = XPackPlugin.resolveConfigFile(environment, "restrictions.yml");

        if (Files.exists(restrictionConfigFilePath)) {
            if (licenseState.checkFeature(XPackLicenseState.Feature.OPERATOR_PRIVILEGES)) {
                final List<RestrictionDescriptor> restrictionDescriptors = RestrictionConfigParser.parseConfig(restrictionConfigFilePath);
                // TODO: only support a single restriction definition for now
                if (restrictionDescriptors.size() != 1) {
                    throw new IllegalArgumentException("Only a single restriction can be defined, got " + restrictionDescriptors.stream()
                        .map(RestrictionDescriptor::getName)
                        .collect(Collectors.joining(",", "[", "]")));
                }
                this.restriction = restrictionDescriptors.get(0).buildRestriction();
            } else {
                logger.warn("Security restriction file is found but current license [{}] does not support it",
                    licenseState.getOperationMode().description());
                this.restriction = null;
            }
        } else {
            logger.debug("Security restriction file [{}] is not found", restrictionConfigFilePath);
            this.restriction = null;
        }
    }

    public void authorize(String action, TransportRequest transportRequest, Authentication authentication) {
        if (restriction != null
            && licenseState.checkFeature(XPackLicenseState.Feature.OPERATOR_PRIVILEGES)) {
            final Connection connection = Connection.fromThreadContext(threadContext);
            if (restriction.permit(action, transportRequest, authentication, connection) == false) {
                throw new ElasticsearchSecurityException(
                    "Action [{}] is not permitted for user [{}] from realm [{}]",
                    RestStatus.FORBIDDEN,
                    action,
                    authentication.getUser().principal(),
                    authentication.getSourceRealm().getName());
            }
        }
    }

    // TODO: license state monitor

}
