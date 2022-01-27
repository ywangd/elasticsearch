/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.metric;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.cache.Cache;
import org.elasticsearch.common.cache.CacheBuilder;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.tasks.Task;

import java.util.List;
import java.util.concurrent.ExecutionException;

public class AuthorizationMetrics {

    private static final Logger logger = LogManager.getLogger(AuthorizationMetrics.class);

    private static final Cache<String, InstantMetric> CACHE_INSTANTANEOUS = CacheBuilder.<String, InstantMetric>builder()
        .setExpireAfterWrite(TimeValue.timeValueMinutes(1))
        .setMaximumWeight(100)
        .build();

    private static final Cache<String, HistogramsRecorder> CACHE_HISTOGRAMS = CacheBuilder.<String, HistogramsRecorder>builder()
        .setExpireAfterAccess(TimeValue.timeValueMinutes(60))
        .setMaximumWeight(100)
        .build();

    private static final HistogramsRecorder TOTAL_HISTOGRAMS = new HistogramsRecorder();

    public static void addHistogramMetric(String xOpaqueId, InstrumentedMethod method, long elapsed) {
        final HistogramsRecorder histogramsRecorder;
        try {
            histogramsRecorder = CACHE_HISTOGRAMS.computeIfAbsent(xOpaqueId, k -> new HistogramsRecorder());
        } catch (ExecutionException e) {
            throw new ElasticsearchException(e);
        }
        histogramsRecorder.recordValue(method, elapsed);
        TOTAL_HISTOGRAMS.recordValue(method, elapsed);
    }

    public static List<HistogramMetric> getMetricHistograms(String xOpaqueId) {
        if (xOpaqueId == null) {
            return TOTAL_HISTOGRAMS.getHistograms();
        } else {
            final HistogramsRecorder histogramsRecorder = CACHE_HISTOGRAMS.get(xOpaqueId);
            if (histogramsRecorder == null) {
                logger.debug("no histogram records found for {} [{}]", Task.X_OPAQUE_ID_HTTP_HEADER, xOpaqueId);
                return List.of();
            }
            return histogramsRecorder.getHistograms();
        }
    }

    public static void addInstantMetric(
        String nodeName,
        String username,
        String xOpaqueId,
        InstrumentedMethod method,
        String action,
        String originatingAction,
        int requestHash,
        int authorizationIndex,
        long startTime,
        long elapsed
    ) {

        final InstantMetric instantMetric;
        try {
            instantMetric = CACHE_INSTANTANEOUS.computeIfAbsent(xOpaqueId, k -> new InstantMetric(nodeName, k));
        } catch (ExecutionException e) {
            throw new ElasticsearchException(e);
        }

        final InstantMetric.InstantMetricMember member = instantMetric.getOrCreateMember(
            action,
            requestHash,
            authorizationIndex,
            startTime
        );

        if (member.username == null) {
            member.username = username;
        }
        assert username.equals(member.username) : "username not the same for a single metricValueMember";
        if (originatingAction != null) {
            if (member.originatingAction == null) {
                member.originatingAction = originatingAction;
            }
            assert originatingAction.equals(member.originatingAction) : "originatingAction not the same for a single metricValueMember";
        } else {
            assert member.originatingAction == null : "originatingAction not always null for a single metricValueMember";
        }

        innerAddInstantMetric(member, method, elapsed);
    }

    public static void addInstantMetric(
        String xOpaqueId,
        InstrumentedMethod method,
        String action,
        int requestHash,
        int authorizationIndex,
        long startTime,
        long elapsed
    ) {
        final InstantMetric instantMetric = CACHE_INSTANTANEOUS.get(xOpaqueId);
        final InstantMetric.InstantMetricMember member = instantMetric.getOrCreateMember(
            action,
            requestHash,
            authorizationIndex,
            startTime
        );

        innerAddInstantMetric(member, method, elapsed);
    }

    private static void innerAddInstantMetric(InstantMetric.InstantMetricMember member, InstrumentedMethod method, long elapsed) {
        switch (method) {
            case RESOLVE_AUTHORIZATION_INFO:
                member.resolveAuthorizationInfoElapsed = elapsed;
                break;
            case AUTHORIZE_RUN_AS:
                member.authorizeRunAsElapsed = elapsed;
                break;
            case AUTHORIZE_CLUSTER_ACTION:
                member.authorizeClusterActionElapsed = elapsed;
                break;
            case AUTHORIZE_INDEX_ACTION:
                member.authorizeIndexActionElapsed = elapsed;
                break;
            case LOAD_AUTHORIZED_INDICES:
                member.loadAuthorizedIndicesElapsed = elapsed;
                break;
            case ROLE_ALLOWED_INDICES_MATCHER:
                member.roleAllowedIndicesMatcherElapsed = elapsed;
                break;
            case ROLE_ALLOWED_ACTIONS_MATCHER:
                member.roleAllowedActionsMatcherElapsed = elapsed;
                break;
            case ROLE_CHECK_RUN_AS:
                member.roleCheckRunAsElapsed = elapsed;
                break;
            case ROLE_CHECK_INDICES_ACTION:
                member.roleCheckIndicesActionElapsed = elapsed;
                break;
            case ROLE_CHECK_CLUSTER_ACTION:
                member.roleCheckClusterActionElapsed = elapsed;
                break;
            case ROLE_AUTHORIZE:
                member.roleAuthorizeElapsed = elapsed;
                break;
            case IAAR_RESOLVE:
                member.iaarResolveElapsed = elapsed;
                break;
            default:
                throw new IllegalArgumentException("Unknown InstrumentedMethod: [{" + method + "}]");
        }
    }

    public static InstantMetric getInstantaneousMetric(String xOpaqueId) {
        // TODO: it really should return a read-only copy of it
        return CACHE_INSTANTANEOUS.get(xOpaqueId);
    }
}
