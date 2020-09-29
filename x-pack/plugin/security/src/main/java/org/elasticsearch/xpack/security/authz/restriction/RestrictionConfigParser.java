/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.restriction;

import org.elasticsearch.common.xcontent.DeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentParserUtils;
import org.elasticsearch.common.xcontent.XContentType;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

public class RestrictionConfigParser {

    public static List<RestrictionDescriptor> parseConfig(Path path) throws IOException {
        try (InputStream in = Files.newInputStream(path, StandardOpenOption.READ)) {
            return parseConfig(in);
        }
    }

    public static List<RestrictionDescriptor> parseConfig(InputStream in) throws IOException {
        final List<RestrictionDescriptor> restrictionDescriptors = new ArrayList<>();
        try (XContentParser parser = yamlParser(in)) {
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
                final String restrictionName = parser.currentName();
                restrictionDescriptors.add(RestrictionDescriptor.parse(restrictionName, parser));
            }
        }
        return List.copyOf(restrictionDescriptors);
    }

    private static XContentParser yamlParser(InputStream in) throws IOException {
        return XContentType.YAML.xContent().createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, in);
    }
}
