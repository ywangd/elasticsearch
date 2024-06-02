/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.telemetry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.Maps;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.core.Releasable;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.plugins.TelemetryPlugin;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.telemetry.metric.Instrument;
import org.elasticsearch.telemetry.metric.MeterRegistry;
import org.elasticsearch.telemetry.tracing.TraceContext;
import org.elasticsearch.telemetry.tracing.Traceable;
import org.elasticsearch.telemetry.tracing.Tracer;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * TelemetryPlugin that uses RecordingMeterRegistry to record meter calls
 * and exposes measurement getters.
 */
public class TestTelemetryPlugin extends Plugin implements TelemetryPlugin {

    protected final RecordingMeterRegistry meter = new RecordingMeterRegistry();

    Registration getRegistration(Instrument instrument) {
        return meter.getRecorder().getRegistration(instrument);
    }

    public List<Measurement> getMetrics(Instrument instrument) {
        return meter.getRecorder().getMeasurements(instrument);
    }

    public List<Measurement> getDoubleCounterMeasurement(String name) {
        return meter.getRecorder().getMeasurements(InstrumentType.DOUBLE_COUNTER, name);
    }

    public List<Measurement> getLongCounterMeasurement(String name) {
        return meter.getRecorder().getMeasurements(InstrumentType.LONG_COUNTER, name);
    }

    public List<Measurement> getLongAsyncCounterMeasurement(String name) {
        return meter.getRecorder().getMeasurements(InstrumentType.LONG_ASYNC_COUNTER, name);
    }

    public List<Measurement> getDoubleUpDownCounterMeasurement(String name) {
        return meter.getRecorder().getMeasurements(InstrumentType.DOUBLE_UP_DOWN_COUNTER, name);
    }

    public List<Measurement> getLongUpDownCounterMeasurement(String name) {
        return meter.getRecorder().getMeasurements(InstrumentType.LONG_UP_DOWN_COUNTER, name);
    }

    public List<Measurement> getDoubleGaugeMeasurement(String name) {
        return meter.getRecorder().getMeasurements(InstrumentType.DOUBLE_GAUGE, name);
    }

    public List<Measurement> getLongGaugeMeasurement(String name) {
        return meter.getRecorder().getMeasurements(InstrumentType.LONG_GAUGE, name);
    }

    public List<Measurement> getDoubleHistogramMeasurement(String name) {
        return meter.getRecorder().getMeasurements(InstrumentType.DOUBLE_HISTOGRAM, name);
    }

    public List<Measurement> getLongHistogramMeasurement(String name) {
        return meter.getRecorder().getMeasurements(InstrumentType.LONG_HISTOGRAM, name);
    }

    public void collect() {
        meter.getRecorder().collect();
    }

    public void resetMeter() {
        meter.getRecorder().resetCalls();
    }

    public ArrayList<String> getRegisteredMetrics(InstrumentType instrumentType) {
        return meter.getRecorder().getRegisteredMetrics(instrumentType);
    }

    // For io.opentelemetry.context.Context
    public static class Context {
        private final Map<String, String> carrier;

        public Context(Map<String, String> carrier) {
            this.carrier = Map.copyOf(carrier);
        }

        public Context with(Object value) {
            // TODO: implement this
            return this;
        }

        static Context current() {
            return new Context(Map.of());
        }
    }

    public enum SpanKind {
        INTERNAL,
        SERVER,
        CLIENT,
        PRODUCER,
        CONSUMER;
    }

    public static class Span {

        private final String name;

        public Span(String name) {
            this.name = name;
        }
    }

    public static class SpanBuilder {
        private final String name;
        private Context parent;
        private Map<String, Object> attributes = new HashMap<>();
        private SpanKind kind;
        private Instant startTimestamp;

        public SpanBuilder(String name) {
            this.name = name;
        }

        public void setParent(Context parent) {
            this.parent = parent;
        }

        public void setAttribute(String key, Object value) {
            attributes.put(key, value);
        }

        public void setSpanKind(SpanKind kind) {
            this.kind = kind;
        }

        public void setStartTimestamp(Instant timestamp) {
            startTimestamp = timestamp;
        }

        public Span startSpan() {
            return new Span(name);
        }
    }

    public static class LoggingTracer implements Tracer {

        private static final Logger logger = LogManager.getLogger(LoggingTracer.class);
        private Map<String, Context> spans = new ConcurrentHashMap<>();

        @Override
        public void startTrace(TraceContext traceContext, Traceable traceable, String name, Map<String, Object> attributes) {
            logger.info("--> startTrace [{}], [{}], [{}], [{}]", traceContext, traceable, name, attributes);
            String spanId = traceable.getSpanId();

            spans.computeIfAbsent(spanId, ignore -> {
                final SpanBuilder spanBuilder = new SpanBuilder(name);
                final Context parentContext = getParentContext(traceContext);
                if (parentContext != null) {
                    spanBuilder.setParent(parentContext);
                }

                setSpanAttributes(traceContext, attributes, spanBuilder);

                Instant startTime = traceContext.getTransient(Task.TRACE_START_TIME);
                if (startTime != null) {
                    spanBuilder.setStartTimestamp(startTime);
                }
                final Span span = spanBuilder.startSpan();
                final Context contextForNewSpan = Context.current().with(span);

                // updateThreadContext(traceContext, contextForNewSpan);
                return contextForNewSpan;
            });
        }

        @Override
        public void startTrace(String name, Map<String, Object> attributes) {
            logger.info("--> startTrace [{}], [{}]", name, attributes);
        }

        @Override
        public void stopTrace(Traceable traceable) {
            logger.info("--> stopTrace [{}]", traceable);
        }

        @Override
        public void stopTrace() {
            logger.info("--> stopTrace");
        }

        @Override
        public void addEvent(Traceable traceable, String eventName) {
            logger.info("--> addEvent [{}], [{}]", traceable, eventName);
        }

        @Override
        public void addError(Traceable traceable, Throwable throwable) {
            logger.info("--> addError [{}], [{}]", traceable, throwable);
        }

        @Override
        public void setAttribute(Traceable traceable, String key, boolean value) {
            logger.info("--> setAttribute [{}], [{}], [{}]", traceable, key, value);
        }

        @Override
        public void setAttribute(Traceable traceable, String key, double value) {
            logger.info("--> setAttribute [{}], [{}], [{}]", traceable, key, value);
        }

        @Override
        public void setAttribute(Traceable traceable, String key, long value) {
            logger.info("--> setAttribute [{}], [{}], [{}]", traceable, key, value);
        }

        @Override
        public void setAttribute(Traceable traceable, String key, String value) {
            logger.info("--> setAttribute [{}], [{}], [{}]", traceable, key, value);
        }

        @Override
        public Releasable withScope(Traceable traceable) {
            logger.info("--> setAttribute [{}]", traceable);
            return () -> {};
        }

        private Context getParentContext(TraceContext traceContext) {
            // Attempt to fetch a local parent context first, otherwise look for a remote parent
            Context parentContext = traceContext.getTransient("parent_" + Task.APM_TRACE_CONTEXT);
            if (parentContext == null) {
                final String traceParentHeader = traceContext.getTransient("parent_" + Task.TRACE_PARENT_HTTP_HEADER);
                final String traceStateHeader = traceContext.getTransient("parent_" + Task.TRACE_STATE);

                if (traceParentHeader != null) {
                    final Map<String, String> traceContextMap = Maps.newMapWithExpectedSize(2);
                    // traceparent and tracestate should match the keys used by W3CTraceContextPropagator
                    traceContextMap.put(Task.TRACE_PARENT_HTTP_HEADER, traceParentHeader);
                    if (traceStateHeader != null) {
                        traceContextMap.put(Task.TRACE_STATE, traceStateHeader);
                    }
                    parentContext = new Context(traceContextMap);
                }
            }
            return parentContext;
        }

        private void setSpanAttributes(TraceContext traceContext, @Nullable Map<String, Object> spanAttributes, SpanBuilder spanBuilder) {
            setSpanAttributes(spanAttributes, spanBuilder);

            final String xOpaqueId = traceContext.getHeader(Task.X_OPAQUE_ID_HTTP_HEADER);
            if (xOpaqueId != null) {
                spanBuilder.setAttribute("es.x-opaque-id", xOpaqueId);
            }
        }

        private void setSpanAttributes(@Nullable Map<String, Object> spanAttributes, SpanBuilder spanBuilder) {
            if (spanAttributes != null) {
                for (Map.Entry<String, Object> entry : spanAttributes.entrySet()) {
                    final String key = entry.getKey();
                    final Object value = entry.getValue();
                    spanBuilder.setAttribute(key, value);
                }

                final boolean isHttpSpan = spanAttributes.keySet().stream().anyMatch(key -> key.startsWith("http."));
                spanBuilder.setSpanKind(isHttpSpan ? SpanKind.SERVER : SpanKind.INTERNAL);
            } else {
                spanBuilder.setSpanKind(SpanKind.INTERNAL);
            }

            // spanBuilder.setAttribute(org.elasticsearch.telemetry.tracing.Tracer.AttributeKeys.NODE_NAME, nodeName);
            // spanBuilder.setAttribute(org.elasticsearch.telemetry.tracing.Tracer.AttributeKeys.CLUSTER_NAME, clusterName);
        }

        private static void updateThreadContext(TraceContext traceContext, Context context) {
            // The new span context can be used as the parent context directly within the same Java process...
            traceContext.putTransient(Task.APM_TRACE_CONTEXT, context);

            // ...whereas for tasks sent to other ES nodes, we need to put trace HTTP headers into the traceContext so
            // that they can be propagated.
            // services.openTelemetry.getPropagators().getTextMapPropagator().inject(context, traceContext, (tc, key, value) -> {
            // if (isSupportedContextKey(key)) {
            // tc.putHeader(key, value);
            // }
            // });
        }
    }

    public static final Tracer LOGGING_TRACER = new LoggingTracer();

    @Override
    public TelemetryProvider getTelemetryProvider(Settings settings) {
        return new TelemetryProvider() {
            @Override
            public Tracer getTracer() {
                return LOGGING_TRACER;
            }

            @Override
            public MeterRegistry getMeterRegistry() {
                return meter;
            }
        };
    }
}
