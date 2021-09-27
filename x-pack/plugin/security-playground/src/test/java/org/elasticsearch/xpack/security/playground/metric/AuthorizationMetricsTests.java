/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.metric;

import org.elasticsearch.test.ESTestCase;

import java.util.Map;
import java.util.stream.IntStream;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class AuthorizationMetricsTests extends ESTestCase {

    public void testMetric() {
        final String nodeName = randomAlphaOfLengthBetween(3, 8);
        final String xOpaqueId = randomAlphaOfLength(20);
        final String username = randomAlphaOfLengthBetween(3, 8);

        final String action1 = randomAlphaOfLength(20);
        final int requestHash1 = randomIntBetween(1, Integer.MAX_VALUE);
        final int authorizationIndex1 = randomIntBetween(0, 5);
        final long startTime1 = randomLong();
        final Long[] elapses1 = addMetrics(nodeName, username, xOpaqueId, action1, requestHash1, authorizationIndex1, startTime1);

        final String action2 = randomAlphaOfLength(20);
        final int requestHash2 = randomIntBetween(1, Integer.MAX_VALUE);
        final int authorizationIndex2 = randomIntBetween(0, 5);
        final long startTime2 = randomLong();
        final Long[] elapses2 = addMetrics(nodeName, username, xOpaqueId, action2, requestHash2, authorizationIndex2, startTime2);

        final InstantMetric metricValue = AuthorizationMetrics.getInstantaneousMetric(xOpaqueId);
        assertThat(metricValue.nodeName, equalTo(nodeName));
        assertThat(metricValue.xOpaqueId, equalTo(xOpaqueId));
        final Map<String, InstantMetric.InstantMetricMember> members = metricValue.members;
        assertThat(members.size(), equalTo(2));
        assertMetricValueMember(action1, requestHash1, authorizationIndex1, startTime1, elapses1, members);
        assertMetricValueMember(action2, requestHash2, authorizationIndex2, startTime2, elapses2, members);
    }

    private void assertMetricValueMember(
        String action,
        int requestHash,
        int authorizationIndex,
        long startTime,
        Long[] elapses,
        Map<String, InstantMetric.InstantMetricMember> members
    ) {
        final String key = action + "@" + requestHash + "@" + authorizationIndex;
        assertThat(members.containsKey(key), is(true));
        final InstantMetric.InstantMetricMember instantMetricMember = members.get(key);
        assertThat(instantMetricMember.startTime, equalTo(startTime));
        assertThat(instantMetricMember.action, equalTo(action));
        assertThat(instantMetricMember.requestHash, equalTo(requestHash));
        assertThat(instantMetricMember.resolveAuthorizationInfoElapsed, equalTo(elapses[0]));
        assertThat(instantMetricMember.authorizeRunAsElapsed, equalTo(elapses[1]));
        assertThat(instantMetricMember.authorizeClusterActionElapsed, equalTo(elapses[2]));
        assertThat(instantMetricMember.authorizeIndexActionElapsed, equalTo(elapses[3]));
        assertThat(instantMetricMember.loadAuthorizedIndicesElapsed, equalTo(elapses[4]));
    }

    private Long[] addMetrics(
        String nodeName,
        String username,
        String xOpaqueId,
        String action,
        int requestHash,
        int authorizationIndex,
        long startTime
    ) {
        final InstrumentedMethod[] methods = InstrumentedMethod.values();
        final Long[] elapses = randomArray(methods.length, methods.length, Long[]::new, () -> randomLongBetween(0, 999999));
        IntStream.range(0, elapses.length)
            .forEach(
                i -> AuthorizationMetrics.addInstantMetric(
                    nodeName,
                    username,
                    xOpaqueId,
                    methods[i],
                    action,
                    action,
                    requestHash,
                    authorizationIndex,
                    startTime,
                    elapses[i]
                )
            );
        return elapses;
    }
}
