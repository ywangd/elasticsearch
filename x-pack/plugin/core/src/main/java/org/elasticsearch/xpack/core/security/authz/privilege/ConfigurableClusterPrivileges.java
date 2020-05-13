/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParseException;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.action.ApiKeyTemplateRequest;
import org.elasticsearch.xpack.core.security.action.privilege.ApplicationPrivilegesRequest;
import org.elasticsearch.xpack.core.security.authz.permission.ClusterPermission;
import org.elasticsearch.xpack.core.security.authz.privilege.ConfigurableClusterPrivilege.Category;
import org.elasticsearch.xpack.core.security.support.Automatons;
import org.elasticsearch.xpack.core.security.xcontent.XContentUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Static utility class for working with {@link ConfigurableClusterPrivilege} instances
 */
public final class ConfigurableClusterPrivileges {

    public static final ConfigurableClusterPrivilege[] EMPTY_ARRAY = new ConfigurableClusterPrivilege[0];

    public static final Writeable.Reader<ConfigurableClusterPrivilege> READER =
        in1 -> in1.readNamedWriteable(ConfigurableClusterPrivilege.class);
    public static final Writeable.Writer<ConfigurableClusterPrivilege> WRITER =
        (out1, value) -> out1.writeNamedWriteable(value);

    private ConfigurableClusterPrivileges() {
    }

    /**
     * Utility method to read an array of {@link ConfigurableClusterPrivilege} objects from a {@link StreamInput}
     */
    public static ConfigurableClusterPrivilege[] readArray(StreamInput in) throws IOException {
        return in.readArray(READER, ConfigurableClusterPrivilege[]::new);
    }

    /**
     * Utility method to write an array of {@link ConfigurableClusterPrivilege} objects to a {@link StreamOutput}
     */
    public static void writeArray(StreamOutput out, ConfigurableClusterPrivilege[] privileges) throws IOException {
        out.writeArray(WRITER, privileges);
    }

    /**
     * Writes a single object value to the {@code builder} that contains each of the provided privileges.
     * The privileges are grouped according to their {@link ConfigurableClusterPrivilege#getCategory() categories}
     */
    public static XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params,
                                             Collection<ConfigurableClusterPrivilege> privileges) throws IOException {
        builder.startObject();
        for (Category category : Category.values()) {
            builder.startObject(category.field.getPreferredName());
            for (ConfigurableClusterPrivilege privilege : privileges) {
                if (category == privilege.getCategory()) {
                    privilege.toXContent(builder, params);
                }
            }
            builder.endObject();
        }
        return builder.endObject();
    }

    /**
     * Read a list of privileges from the parser. The parser should be positioned at the
     * {@link XContentParser.Token#START_OBJECT} token for the privileges value
     */
    public static List<ConfigurableClusterPrivilege> parse(XContentParser parser) throws IOException {
        List<ConfigurableClusterPrivilege> privileges = new ArrayList<>();

        expectedToken(parser.currentToken(), parser, XContentParser.Token.START_OBJECT);
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            expectedToken(parser.currentToken(), parser, XContentParser.Token.FIELD_NAME);

            final Category category = matchCategoryFieldName(parser);
            expectedToken(parser.nextToken(), parser, XContentParser.Token.START_OBJECT);
            if (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                expectedToken(parser.currentToken(), parser, XContentParser.Token.FIELD_NAME);
                switch (category) {
                    case APPLICATION:
                        expectFieldName(parser, ManageApplicationPrivileges.Fields.MANAGE);
                        privileges.add(ManageApplicationPrivileges.parse(parser));
                        expectedToken(parser.nextToken(), parser, XContentParser.Token.END_OBJECT);
                        break;
                    case API_KEY_TEMPLATE:
                        privileges.add(ManageApiKeyTemplatePrivilege.parse(parser));
                        break;
                    default:
                        throw new IllegalStateException(String.format(Locale.ROOT, "Unhandled category: %s", category));
                }

            }
        }

        return privileges;
    }

    private static void expectedToken(XContentParser.Token read, XContentParser parser, XContentParser.Token expected) {
        if (read != expected) {
            throw new XContentParseException(parser.getTokenLocation(),
                "failed to parse privilege. expected [" + expected + "] but found [" + read + "] instead");
        }
    }

    private static void expectFieldName(XContentParser parser, ParseField... fields) throws IOException {
        final String fieldName = parser.currentName();
        if (Arrays.stream(fields).anyMatch(pf -> pf.match(fieldName, parser.getDeprecationHandler())) == false) {
            throw new XContentParseException(parser.getTokenLocation(),
                "failed to parse privilege. expected " + (fields.length == 1 ? "field name" : "one of") + " ["
                    + Strings.arrayToCommaDelimitedString(fields) + "] but found [" + fieldName + "] instead");
        }
    }

    private static Category matchCategoryFieldName(XContentParser parser) throws IOException {
        final String fieldName = parser.currentName();
        for (Category category : Category.values()) {
            if (category.field.match(fieldName, parser.getDeprecationHandler())) {
                return category;
            }
        }
        throw new XContentParseException(parser.getTokenLocation(),
            "failed to parse privilege. expected " + (Category.values().length == 1 ? "field name" : "one of") + " ["
                + Strings.arrayToCommaDelimitedString(Category.values()) + "] but found [" + fieldName + "] instead");
    }

    /**
     * The {@code ManageApplicationPrivileges} privilege is a {@link ConfigurableClusterPrivilege} that grants the
     * ability to execute actions related to the management of application privileges (Get, Put, Delete) for a subset
     * of applications (identified by a wildcard-aware application-name).
     */
    public static class ManageApplicationPrivileges implements ConfigurableClusterPrivilege {
        public static final String WRITEABLE_NAME = "manage-application-privileges";

        private final Set<String> applicationNames;
        private final Predicate<String> applicationPredicate;
        private final Predicate<TransportRequest> requestPredicate;

        public ManageApplicationPrivileges(Set<String> applicationNames) {
            this.applicationNames = Collections.unmodifiableSet(applicationNames);
            this.applicationPredicate = Automatons.predicate(applicationNames);
            this.requestPredicate = request -> {
                if (request instanceof ApplicationPrivilegesRequest) {
                    final ApplicationPrivilegesRequest privRequest = (ApplicationPrivilegesRequest) request;
                    final Collection<String> requestApplicationNames = privRequest.getApplicationNames();
                    return requestApplicationNames.isEmpty() ? this.applicationNames.contains("*")
                        : requestApplicationNames.stream().allMatch(application -> applicationPredicate.test(application));
                }
                return false;
            };

        }

        @Override
        public Category getCategory() {
            return Category.APPLICATION;
        }

        public Collection<String> getApplicationNames() {
            return Collections.unmodifiableCollection(this.applicationNames);
        }

        @Override
        public String getWriteableName() {
            return WRITEABLE_NAME;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeCollection(this.applicationNames, StreamOutput::writeString);
        }

        public static ManageApplicationPrivileges createFrom(StreamInput in) throws IOException {
            final Set<String> applications = in.readSet(StreamInput::readString);
            return new ManageApplicationPrivileges(applications);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            return builder.field(Fields.MANAGE.getPreferredName(),
                Collections.singletonMap(Fields.APPLICATIONS.getPreferredName(), applicationNames)
            );
        }

        public static ManageApplicationPrivileges parse(XContentParser parser) throws IOException {
            expectedToken(parser.currentToken(), parser, XContentParser.Token.FIELD_NAME);
            expectFieldName(parser, Fields.MANAGE);
            expectedToken(parser.nextToken(), parser, XContentParser.Token.START_OBJECT);
            expectedToken(parser.nextToken(), parser, XContentParser.Token.FIELD_NAME);
            expectFieldName(parser, Fields.APPLICATIONS);
            expectedToken(parser.nextToken(), parser, XContentParser.Token.START_ARRAY);
            final String[] applications = XContentUtils.readStringArray(parser, false);
            expectedToken(parser.nextToken(), parser, XContentParser.Token.END_OBJECT);
            return new ManageApplicationPrivileges(new LinkedHashSet<>(Arrays.asList(applications)));
        }

        @Override
        public String toString() {
            return "{" + getCategory() + ":" + Fields.MANAGE.getPreferredName() + ":" + Fields.APPLICATIONS.getPreferredName() + "="
                + Strings.collectionToDelimitedString(applicationNames, ",") + "}";
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final ManageApplicationPrivileges that = (ManageApplicationPrivileges) o;
            return this.applicationNames.equals(that.applicationNames);
        }

        @Override
        public int hashCode() {
            return applicationNames.hashCode();
        }

        @Override
        public ClusterPermission.Builder buildPermission(final ClusterPermission.Builder builder) {
            return builder.add(this, Set.of("cluster:admin/xpack/security/privilege/*"), requestPredicate);
        }

        private interface Fields {
            ParseField MANAGE = new ParseField("manage");
            ParseField APPLICATIONS = new ParseField("applications");
        }
    }

    public static class ManageApiKeyTemplatePrivilege implements ConfigurableClusterPrivilege {
        public static final String WRITEABLE_NAME = "manage-api-key-template-privileges";

        private final Map<String, Set<String>> actionToTemplateNames;
        private final Map<String, Predicate<String>> actionToTemplatePredicate;
        private final Predicate<TransportRequest> requestPredicate;

        public ManageApiKeyTemplatePrivilege(Map<String, Set<String>> actionToTemplateNames) {
            this.actionToTemplateNames = Collections.unmodifiableMap(actionToTemplateNames);
            actionToTemplatePredicate = this.actionToTemplateNames.entrySet()
                .stream()
                .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, e -> Automatons.predicate(e.getValue())));
            this.requestPredicate = request -> {
                if (request instanceof ApiKeyTemplateRequest) {
                    final ApiKeyTemplateRequest templateRequest = (ApiKeyTemplateRequest) request;
                    final Predicate<String> templatePredicate = actionToTemplatePredicate.get(templateRequest.getAction());
                    final Set<String> templateNames = actionToTemplateNames.get(templateRequest.getAction());
                    if (templatePredicate == null || templateNames == null) {
                        return false;
                    }
                    templateRequest.getTemplateName();
                    return templateNames.contains("*") || templatePredicate.test(templateRequest.getTemplateName());
                }
                return false;
            };
        }

        @Override
        public Category getCategory() {
            return Category.API_KEY_TEMPLATE;
        }

        @Override
        public String getWriteableName() {
            return WRITEABLE_NAME;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeMap(this.actionToTemplateNames.entrySet().stream().collect(
                Collectors.toUnmodifiableMap(Map.Entry::getKey, e -> (Object) e.getValue())));
        }

        public static ManageApiKeyTemplatePrivilege createFrom(StreamInput in) throws IOException {
            final Map<String, Set<String>> actionToTemplateNames =
                in.readMap(StreamInput::readString, (i) -> i.readSet(StreamInput::readString));
            return new ManageApiKeyTemplatePrivilege(actionToTemplateNames);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            for (Map.Entry<String, Set<String>> entry : actionToTemplateNames.entrySet()) {
                builder.field(entry.getKey(), Map.of(Fields.TEMPLATES.getPreferredName(), entry.getValue()));
            }
            return builder;
        }

        public static ManageApiKeyTemplatePrivilege parse(XContentParser parser) throws IOException {
            final Map<String, Set<String>> actionToTemplates = new HashMap<>();
            do {
                expectedToken(parser.currentToken(), parser, XContentParser.Token.FIELD_NAME);
                expectFieldName(parser, Fields.MANAGE, Fields.INVOKE, Fields.INVOKE_SYNC);
                final String action = parser.currentName();
                expectedToken(parser.nextToken(), parser, XContentParser.Token.START_OBJECT);
                expectedToken(parser.nextToken(), parser, XContentParser.Token.FIELD_NAME);
                expectFieldName(parser, Fields.TEMPLATES);
                expectedToken(parser.nextToken(), parser, XContentParser.Token.START_ARRAY);
                final String[] templates = XContentUtils.readStringArray(parser, false);
                actionToTemplates.put(action, templates == null ? Set.of() : Set.of(templates));
                expectedToken(parser.nextToken(), parser, XContentParser.Token.END_OBJECT);
            } while(parser.nextToken() != XContentParser.Token.END_OBJECT);

            return new ManageApiKeyTemplatePrivilege(actionToTemplates);
        }

        @Override
        public String toString() {
            return "{" + getCategory() + ":"
                + actionToTemplateNames.entrySet().stream().map(e -> e.getKey() + ":" + Fields.TEMPLATES.getPreferredName() + "="
                + Strings.collectionToDelimitedString(e.getValue(), ",")).collect(Collectors.joining(":"))
                + "}";
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final ManageApiKeyTemplatePrivilege that = (ManageApiKeyTemplatePrivilege) o;
            return this.actionToTemplateNames.equals(that.actionToTemplateNames);
        }

        @Override
        public int hashCode() {
            return actionToTemplateNames.hashCode();
        }

        @Override
        public ClusterPermission.Builder buildPermission(final ClusterPermission.Builder builder) {
            return builder.add(this, Set.of("cluster:admin/xpack/security/api_key_template/*"), requestPredicate);
        }

        private interface Fields {
            ParseField MANAGE = new ParseField("manage");
            ParseField INVOKE = new ParseField("invoke");
            ParseField INVOKE_SYNC = new ParseField("invoke_sync");
            ParseField TEMPLATES = new ParseField("templates");
        }
    }
}
