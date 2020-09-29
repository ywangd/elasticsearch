/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.restriction;

import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.security.authz.restriction.Predicates.ActionBiPredicate;
import org.elasticsearch.xpack.security.authz.restriction.Predicates.UserBiPredicate;

public class Restriction {

    private final String name;
    private final ActionBiPredicate actionBiPredicate;
    private final UserBiPredicate allowedUserBiPredicate;

    public Restriction(String name, ActionBiPredicate actionBiPredicate, UserBiPredicate allowedUserBiPredicate) {
        this.name = name;
        this.actionBiPredicate = actionBiPredicate;
        this.allowedUserBiPredicate = allowedUserBiPredicate;
    }

    public boolean permit(String action, TransportRequest transportRequest, Authentication authentication, Connection connection) {
        if (isActionRestricted(action, transportRequest)) {
            return isUserAllowed(authentication, connection);
        } else {
            return true;
        }
    }

    private boolean isActionRestricted(String action, TransportRequest transportRequest) {
        return actionBiPredicate.test(action, transportRequest);
    }

    private boolean isUserAllowed(Authentication authentication, Connection connection) {
        return allowedUserBiPredicate.test(authentication, connection);
    }
}
