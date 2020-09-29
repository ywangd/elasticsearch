/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.restriction;

import org.elasticsearch.test.ESTestCase;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class RestrictionConfigParserTests extends ESTestCase {

    public void testParseConfig() throws IOException {
        final String config = ""
            + "operator:\n"
            + "  restricted:\n"
            + "    actions:\n"
            + "      - name: \"cluster:admin/autoscale/*\"\n"
            + "      - name: \"cluster:admin/settings/update\"\n"
            + "      - name: \"indices:*\"\n"
            + "  allow:\n"
            + "    - usernames: [\"found_agent_1\",\"found_agent_2\"]\n"
            + "      realm_name: \"found\"\n"
            + "      realm_type: \"file\"\n"
            + "      auth_type: \"REALM\"\n"
            + "    - usernames: [\"found_internal_system\"]\n"
            + "      realm_name: \"found\"\n"
            + "      realm_type: \"file\"\n"
            + "      auth_type: \"REALM\"\n";

        try (ByteArrayInputStream in = new ByteArrayInputStream(config.getBytes(StandardCharsets.UTF_8))) {
            final List<RestrictionDescriptor> restrictionDescriptors = RestrictionConfigParser.parseConfig(in);
            assertEquals(1, restrictionDescriptors.size());
            System.out.println(restrictionDescriptors.get(0));
        }
    }

}
