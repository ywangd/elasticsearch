/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.restriction;

import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.support.Automatons;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Predicate;

public class Predicates {

    private Predicates() {
    }

    public interface UserBiPredicate extends BiPredicate<Authentication, Connection> {
    }

    public static class SimpleUserBiPredicate implements UserBiPredicate {
        private final boolean allowRunAs;
        private final Set<String> usernames;
        private final String realmName;
        private final String realmType;
        private final Authentication.AuthenticationType authType;

        public SimpleUserBiPredicate(
            Set<String> usernames,
            String realmName,
            String realmType,
            Authentication.AuthenticationType authType,
            boolean allowRunAs
            ) {
            this.usernames = usernames;
            this.realmName = realmName;
            this.realmType = realmType;
            this.authType = authType;
            this.allowRunAs = allowRunAs;
        }

        @Override
        public boolean test(Authentication authentication, Connection connection) {
            if (authentication.getUser().isRunAs() && allowRunAs == false) {
                return false;
            }
            return usernames.contains(authentication.getUser().principal())
                && realmName.equals(authentication.getSourceRealm().getName())
                && realmType.equals(authentication.getSourceRealm().getType())
                && authType == authentication.getAuthenticationType();
        }
    }

    public static class AuthConnectionUserBiPredicate extends SimpleUserBiPredicate {

        private final Connection.ConnectionPredicate connectionPredicate;

        public AuthConnectionUserBiPredicate(
            Set<String> usernames,
            String realmName,
            String realmType,
            Authentication.AuthenticationType authType,
            boolean allowRunAs,
            Connection.ConnectionPredicate connectionPredicate) {
            super(usernames, realmName, realmType, authType, allowRunAs);
            this.connectionPredicate = Objects.requireNonNull(connectionPredicate);
        }

        @Override
        public boolean test(Authentication authentication, Connection connection) {
            if (super.test(authentication, connection) == false) {
                return false;
            } else {
                return connectionPredicate.test(connection);
            }
        }
    }

    public static class ChainedUserBiPredicate implements UserBiPredicate {
        private final List<UserBiPredicate> predicates;

        public ChainedUserBiPredicate(List<UserBiPredicate> predicates) {
            this.predicates = List.copyOf(predicates);
        }

        @Override
        public boolean test(Authentication authentication, Connection connection) {
            return predicates.stream().anyMatch(predicate -> predicate.test(authentication, connection));
        }
    }

    public interface ActionBiPredicate extends BiPredicate<String, TransportRequest> {
    }

    public static class SimpleActionBiPredicate implements ActionBiPredicate {

        private final Predicate<String> actionPredicate;

        public SimpleActionBiPredicate(String... actions) {
            this.actionPredicate = Automatons.predicate(actions);
        }

        @Override
        public boolean test(String action, TransportRequest transportRequest) {
            return actionPredicate.test(action);
        }
    }

    public static class ActionRequestActionBiPredicate extends SimpleActionBiPredicate {

        private final Predicate<TransportRequest> requestPredicate;

        public ActionRequestActionBiPredicate(String action, Predicate<TransportRequest> requestPredicate) {
            super(action);
            this.requestPredicate = requestPredicate;
        }

        @Override
        public boolean test(String action, TransportRequest transportRequest) {
            return super.test(action, transportRequest) && requestPredicate.test(transportRequest);
        }
    }

    public static class ChainedActionBiPredicate implements ActionBiPredicate {

        private final List<ActionBiPredicate> predicates;

        public ChainedActionBiPredicate(Collection<ActionBiPredicate> predicates) {
            this.predicates = List.copyOf(predicates);
        }

        @Override
        public boolean test(String action, TransportRequest transportRequest) {
            return predicates.stream().anyMatch(predicate -> predicate.test(action, transportRequest));
        }
    }

}
