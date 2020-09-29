/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.restriction;

import org.apache.logging.log4j.util.Strings;
import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.xcontent.XContentUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class RestrictionDescriptor {

    private final String name;
    private final Restricted restricted;
    private final List<UserQualifier> allowedUserQualifiers;

    private RestrictionDescriptor(String name,
                                 Restricted restricted,
                                 List<UserQualifier> allowedUserQualifiers) {
        this.name = name;
        this.restricted = restricted;
        this.allowedUserQualifiers = allowedUserQualifiers;
    }

    public Restriction buildRestriction() {
        final Predicates.SimpleActionBiPredicate actionBiPredicate =
            new Predicates.SimpleActionBiPredicate(restricted.actionQualifiers.stream().map(aq -> aq.actionName).toArray(String[]::new));

        final List<Predicates.UserBiPredicate> userBiPredicates = allowedUserQualifiers.stream()
            .map(auq -> new Predicates.SimpleUserBiPredicate(auq.usernames, auq.realmName, auq.realmType, auq.authType, auq.allowRunAs))
            .collect(Collectors.toList());

        return new Restriction(name, actionBiPredicate, new Predicates.ChainedUserBiPredicate(userBiPredicates));
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return "RestrictionDescriptor{" + "name='" + name + '\'' + ", restricted=" + restricted + ", allowedUserQualifiers=" + allowedUserQualifiers + '}';
    }

    public static RestrictionDescriptor parse(String restrictionName, XContentParser parser) throws IOException {
        if (Strings.isBlank(restrictionName)) {
            throw new IllegalArgumentException("Restriction must have a name");
        }

        XContentParser.Token token = parser.nextToken();
        if (token != XContentParser.Token.START_OBJECT) {
            throw new ElasticsearchParseException(
                "failed to parse restriction [{}]. expected an object but found [{}] instead", restrictionName, token);
        }
        Restricted restricted = null;
        List<UserQualifier> allowedUserQualifiers = null;
        String currentFieldName = null;
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (Fields.RESTRICTED.match(currentFieldName, parser.getDeprecationHandler())) {
                restricted = parseRestricted(restrictionName, parser);
            } else if (Fields.ALLOW.match(currentFieldName, parser.getDeprecationHandler())) {
                allowedUserQualifiers = parseUserQualifiers(restrictionName, parser);
            } else {
                throw unexpectedFieldException("restriction", restrictionName, currentFieldName);
            }
        }

        if (restricted == null) {
            throw missingRequiredFieldException("restricted", restrictionName, Fields.RESTRICTED.getPreferredName());
        }
        if (allowedUserQualifiers == null) {
            throw missingRequiredFieldException("allowed user qualifiers", restrictionName, Fields.ALLOW.getPreferredName());
        }

        return new RestrictionDescriptor(restrictionName, restricted, allowedUserQualifiers);

    }

    private static Restricted parseRestricted(String restrictionName, XContentParser parser) throws IOException {
        XContentParser.Token token = parser.currentToken();
        if (token != XContentParser.Token.START_OBJECT) {
            throw mismatchedFieldException("restricted", restrictionName, parser.currentName(), "object", token);
        }
        List<ActionQualifier> actionQualifiers = null;
        String currentFieldName = null;
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (Fields.ACTIONS.match(currentFieldName, parser.getDeprecationHandler())) {
                actionQualifiers = parseActions(restrictionName, parser);
            } else {
                throw unexpectedFieldException("restricted", restrictionName, currentFieldName);
            }
        }
        if (actionQualifiers == null) {
            throw missingRequiredFieldException("restricted", restrictionName, Fields.ACTIONS.getPreferredName());
        }
        return new Restricted(actionQualifiers);
    }

    private static List<ActionQualifier> parseActions(String restrictionName, XContentParser parser) throws IOException {
        XContentParser.Token token = parser.currentToken();
        if (token != XContentParser.Token.START_ARRAY) {
            throw mismatchedFieldException("actions", restrictionName, parser.currentName(), "array", token);
        }
        List<ActionQualifier> actionQualifiers = new ArrayList<>();
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            actionQualifiers.add(parseAction(restrictionName, parser));
        }
        if (actionQualifiers.isEmpty()) {
            throw new ElasticsearchParseException(
                "failed to parse actions for restriction [{}]. actions must not be empty",
                restrictionName);
        }
        return actionQualifiers;
    }

    private static ActionQualifier parseAction(String restrictionName, XContentParser parser) throws IOException {
        XContentParser.Token token = parser.currentToken();
        if (token != XContentParser.Token.START_OBJECT) {
            throw mismatchedFieldException("action", restrictionName, parser.currentName(), "object", token);
        }
        String actionName = null;
        String currentFieldName = null;
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (Fields.ACTION_NAME.match(currentFieldName, parser.getDeprecationHandler())) {
                if (token == XContentParser.Token.VALUE_STRING) {
                    actionName = parser.text();
                } else {
                    throw mismatchedFieldException("action name", restrictionName, currentFieldName, "string", token);
                }
            } else {
                // TODO: parameters
                throw unexpectedFieldException("action", restrictionName, currentFieldName);
            }
        }
        if (actionName == null) {
            throw missingRequiredFieldException("action", restrictionName, Fields.ACTION_NAME.getPreferredName());
        }
        return new ActionQualifier(actionName);
    }

    private static List<UserQualifier> parseUserQualifiers(String restrictionName, XContentParser parser) throws IOException {
        XContentParser.Token token = parser.currentToken();
        if (token != XContentParser.Token.START_ARRAY) {
            throw mismatchedFieldException("users", restrictionName, parser.currentName(), "array", token);
        }
        List<UserQualifier> userQualifiers = new ArrayList<>();
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            userQualifiers.add(parseUserQualifier(restrictionName, parser));
        }
        if (userQualifiers.isEmpty()) {
            throw new ElasticsearchParseException(
                "failed to parse users for restriction [{}]. users must not be empty",
                restrictionName);
        }
        return userQualifiers;
    }

    private static UserQualifier parseUserQualifier(String restrictionName, XContentParser parser) throws IOException {
        XContentParser.Token token = parser.currentToken();
        if (token != XContentParser.Token.START_OBJECT) {
            throw mismatchedFieldException("user", restrictionName, parser.currentName(), "object", token);
        }
        String[] usernames = null;
        String realmName = null;
        String realmType = null;
        Authentication.AuthenticationType authType = null;
        String currentFieldName = null;
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (Fields.USERNAMES.match(currentFieldName, parser.getDeprecationHandler())) {
                usernames = XContentUtils.readStringArray(parser, false);
            } else if (Fields.REALM_NAME.match(currentFieldName, parser.getDeprecationHandler())) {
                if (token == XContentParser.Token.VALUE_STRING) {
                    realmName = parser.text();
                } else {
                    throw mismatchedFieldException("realm name", restrictionName, currentFieldName, "string", token);
                }
            } else if (Fields.REALM_TYPE.match(currentFieldName, parser.getDeprecationHandler())) {
                if (token == XContentParser.Token.VALUE_STRING) {
                    realmType = parser.text();
                } else {
                    throw mismatchedFieldException("realm type", restrictionName, currentFieldName, "string", token);
                }
            } else if (Fields.AUTH_TYPE.match(currentFieldName, parser.getDeprecationHandler())) {
                if (token == XContentParser.Token.VALUE_STRING) {
                    authType = Authentication.AuthenticationType.valueOf(parser.text().toUpperCase(Locale.ROOT));
                } else {
                    throw mismatchedFieldException("authentication type", restrictionName, currentFieldName, "string", token);
                }
            } else {
                throw unexpectedFieldException("user", restrictionName, currentFieldName);
            }
        }
        if (usernames == null) {
            throw missingRequiredFieldException("usernames", restrictionName, Fields.USERNAMES.getPreferredName());
        }
        if (realmName == null) {
            throw missingRequiredFieldException("realm name", restrictionName, Fields.REALM_NAME.getPreferredName());
        }
        if (realmType == null) {
            throw missingRequiredFieldException("realm type", restrictionName, Fields.REALM_TYPE.getPreferredName());
        }
        if (authType == null) {
            throw missingRequiredFieldException("authentication type", restrictionName, Fields.AUTH_TYPE.getPreferredName());
        }
        return new UserQualifier(Set.of(usernames), realmName, realmType, authType);
    }

    private static ElasticsearchParseException mismatchedFieldException(String entityName, String restrictionName,
                                                                        String fieldName, String expectedType,
                                                                        XContentParser.Token token) {
        return new ElasticsearchParseException(
            "failed to parse {} for restriction [{}]. " +
                "expected field [{}] value to be {}, but found an element of type [{}]",
            entityName, restrictionName, fieldName, expectedType, token);
    }

    private static ElasticsearchParseException missingRequiredFieldException(String entityName,
                                                                             String restrictionName,
                                                                             String fieldName) {
        return new ElasticsearchParseException(
            "failed to parse {} for restriction [{}]. missing required [{}] field",
            entityName, restrictionName, fieldName);
    }

    private static ElasticsearchParseException unexpectedFieldException(String entityName,
                                                                        String restrictionName,
                                                                        String fieldName) {
        return new ElasticsearchParseException(
            "failed to parse {} for restriction [{}]. unexpected field [{}]",
            entityName, restrictionName, fieldName);
    }

    public static class Restricted {
        private final List<ActionQualifier> actionQualifiers;

        public Restricted(List<ActionQualifier> actionQualifiers) {
            this.actionQualifiers = actionQualifiers;
        }

        @Override
        public String toString() {
            return "Restricted{" + "actionQualifiers=" + actionQualifiers + '}';
        }
    }

    public static class ActionQualifier {
        private final String actionName;
        @Nullable
        private final Map<String, Object> parameters;

        public ActionQualifier(String actionName) {
            this.actionName = actionName;
            this.parameters = null;
        }

        @Override
        public String toString() {
            return "ActionQualifier{" + "actionName='" + actionName + '\'' + ", parameters=" + parameters + '}';
        }
    }

    public static class ConnectionQualifier {
        private final List<String> certificateAuthorities;
        private final int port;
        private final String remoteAddress;

        public ConnectionQualifier(List<String> certificateAuthorities, int port, String remoteAddress) {
            this.certificateAuthorities = certificateAuthorities;
            this.port = port;
            this.remoteAddress = remoteAddress;
        }

        @Override
        public String toString() {
            return "ConnectionQualifier{" + "certificateAuthorities=" + certificateAuthorities + ", port=" + port + ", remoteAddress='" + remoteAddress + '\'' + '}';
        }
    }

    public static class UserQualifier {
        private final Set<String> usernames;
        private final String realmName;
        private final String realmType;
        private final Authentication.AuthenticationType authType;
        @Nullable
        private final ConnectionQualifier connectionQualifier;
        private final boolean allowRunAs;

        public UserQualifier(
            Set<String> usernames,
            String realmName,
            String realmType,
            Authentication.AuthenticationType authType) {
            this.usernames = usernames;
            this.realmName = realmName;
            this.realmType = realmType;
            this.authType = authType;
            this.connectionQualifier = null;
            this.allowRunAs = false;
        }

        @Override
        public String toString() {
            return "UserQualifier{" + "usernames=" + usernames + ", realmName='" + realmName + '\'' + ", realmType='" + realmType + '\'' + ", authType=" + authType + ", connectionQualifier=" + connectionQualifier + ", allowRunAs=" + allowRunAs + '}';
        }
    }

    public interface Fields {
        ParseField RESTRICTED = new ParseField("restricted");
        ParseField ACTIONS = new ParseField("actions");
        ParseField ACTION_NAME = new ParseField("name");
        ParseField ALLOW = new ParseField("allow");
        ParseField USERNAMES = new ParseField("usernames");
        ParseField REALM_NAME = new ParseField("realm_name");
        ParseField REALM_TYPE = new ParseField("realm_type");
        ParseField AUTH_TYPE = new ParseField("auth_type");
    }
}
