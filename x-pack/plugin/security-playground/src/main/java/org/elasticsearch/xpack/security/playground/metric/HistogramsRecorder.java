/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.metric;

import org.HdrHistogram.Histogram;
import org.HdrHistogram.Recorder;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

public class HistogramsRecorder {

    Map<Enum<InstrumentedMethod>, Entry> entries = new ConcurrentHashMap<>();

    public void recordValue(InstrumentedMethod method, long elapsed) {
        final Entry entry = entries.computeIfAbsent(method, k -> new Entry());
        entry.recorder.recordValue(elapsed);
    }

    public List<HistogramMetric> getHistograms() {
        return Arrays.stream(InstrumentedMethod.values()).map(method -> {
            final Entry entry = entries.get(method);
            if (entry == null) {
                return HistogramMetric.empty(method);
            }
            final Histogram histogram = entry.recorder.getIntervalHistogram(entry.histogram.get());
            final HistogramMetric histogramMetric = new HistogramMetric(
                method,
                histogram.getTotalCount(),
                histogram.getMinValue(),
                histogram.getMaxValue(),
                (long) histogram.getMean(),
                histogram.getValueAtPercentile(10.0),
                histogram.getValueAtPercentile(50.0),
                histogram.getValueAtPercentile(90.0),
                histogram.getValueAtPercentile(99.0)
            );
            entry.histogram.set(histogram);
            return histogramMetric;
        }).collect(Collectors.toUnmodifiableList());
    }

    static class Entry {
        Recorder recorder = new Recorder(1, TimeUnit.SECONDS.toNanos(60), 3);
        AtomicReference<Histogram> histogram = new AtomicReference<>(recorder.getIntervalHistogram());
    }
}
