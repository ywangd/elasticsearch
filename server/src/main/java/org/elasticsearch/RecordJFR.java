/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch;

import jdk.jfr.Category;
import jdk.jfr.Event;
import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;
import org.HdrHistogram.Histogram;
import org.HdrHistogram.Recorder;
import org.HdrHistogram.SynchronizedHistogram;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.metrics.MeanMetric;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@SuppressForbidden(reason = "JFR")
public class RecordJFR {

    private static Map<String, Long> authenticationStatsCache = new ConcurrentHashMap<>();
    private static Map<String, Long> authorizationStatsCache = new ConcurrentHashMap<>();
    private static Map<String, Integer> authenticationCount = new ConcurrentHashMap<>();
    private static Map<String, Integer> authorizationCount = new ConcurrentHashMap<>();

    public static void incAuthenticationCount(String opaque) {
        authenticationCount.put(opaque, authenticationCount.getOrDefault(opaque, 0) + 1);
    }

    public static void addAuthenticationDuration(String opaque, long duration) {
        final int count = authenticationCount.getOrDefault(opaque, 0);
        if (count == 1) {
            authenticationStatsCache.put(opaque, authenticationStatsCache.getOrDefault(opaque, 0L) + duration);
        }
        authenticationCount.put(opaque, count - 1);
    }

    public static long getAuthenticationDuration(String opaque) {
        return authenticationStatsCache.getOrDefault(opaque, 0L);
    }

    public static void incAuthorizationCount(String opaque) {
        authorizationCount.put(opaque, authorizationCount.getOrDefault(opaque, 0) + 1);
    }

    public static void addAuthorizationDuration(String opaque, long duration) {
        final int count = authorizationCount.getOrDefault(opaque, 0);
        if (count == 1) {
            authorizationStatsCache.put(opaque, authorizationStatsCache.getOrDefault(opaque, 0L) + duration);
        }
        authorizationCount.put(opaque, count - 1);
    }

    public static long getAuthorizationDuration(String opaque) {
        return authorizationStatsCache.getOrDefault(opaque, 0L);
    }

    public static void removeAuthDuration(String opaque) {
        authenticationStatsCache.remove(opaque);
        authorizationStatsCache.remove(opaque);
        authenticationCount.remove(opaque);
        authorizationCount.remove(opaque);
    }

    public static synchronized void recordHistogram(String name, Histogram histogram, HistogramEvent event) {
        if (event.isEnabled() == false) {
            return;
        }

        event.begin();
        event._10 = histogram.getValueAtPercentile(10.0);
        event._50 = histogram.getValueAtPercentile(50.0);
        event._90 = histogram.getValueAtPercentile(90.0);
        event._99 = histogram.getValueAtPercentile(99.0);
        event._99_9 = histogram.getValueAtPercentile(99.9);
        event._99_99 = histogram.getValueAtPercentile(99.99);
        event._99_999 = histogram.getValueAtPercentile(99.999);
        event.max = histogram.getMaxValue();
        event.mean = histogram.getMean();
        event.total = histogram.getTotalCount();
        event.name = name;
        event.end();
        event.commit();
    }

    public static synchronized void recordMeanMetric(String name, MeanMetric meanMetric) {
        MeanMetricEvent event = new MeanMetricEvent();
        if (event.isEnabled() == false) {
            return;
        }

        event.begin();
        event.mean = meanMetric.mean();
        event.sum = meanMetric.sum();
        event.counter = meanMetric.count();
        event.name = name;
        event.end();
        event.commit();
    }

    public static void scheduleMeanSample(String name, ThreadPool threadPool, AtomicReference<MeanMetric> meanMetric) {
        threadPool.scheduleWithFixedDelay(new Runnable() {
            @Override
            public void run() {
                synchronized (RecordJFR.class) {
                    MeanMetric meanMetric1 = meanMetric.getAndSet(new MeanMetric());
                    RecordJFR.recordMeanMetric(name, meanMetric1);
                }
            }
        }, TimeValue.timeValueSeconds(10), ThreadPool.Names.GENERIC);
    }

    public static void scheduleHistogramSample(String name, ThreadPool threadPool, AtomicReference<Recorder> recorder) {
        Histogram initialHistogram = recorder.get().getIntervalHistogram(null);
        SynchronizedHistogram totalHistogram = new SynchronizedHistogram(initialHistogram.getLowestDiscernibleValue(),
            initialHistogram.getHighestTrackableValue(), initialHistogram.getNumberOfSignificantValueDigits());
        totalHistogram.add(initialHistogram);
        AtomicReference<Histogram> toReuse = new AtomicReference<>(initialHistogram);

        threadPool.scheduleWithFixedDelay(new Runnable() {
            @Override
            public void run() {
                synchronized (RecordJFR.class) {
                    Histogram histogramToRecycle = toReuse.get();
                    histogramToRecycle.reset();

                    Histogram intervalHistogram = recorder.get().getIntervalHistogram(histogramToRecycle);
                    toReuse.set(intervalHistogram);
                    totalHistogram.add(intervalHistogram);
                    RecordJFR.recordHistogram(name, intervalHistogram, new IntervalHistogramEvent());
                    RecordJFR.recordHistogram(name, totalHistogram, new TotalHistogramEvent());
                }
            }
        }, TimeValue.timeValueSeconds(10), ThreadPool.Names.GENERIC);
    }

    public static long toMicrosMaxMinute(long nanos) {
        return Math.min(TimeUnit.NANOSECONDS.toMicros(nanos), TimeUnit.MINUTES.toMicros(1));
    }

    public static long toNanosMaxSecond(long nanos) {
        return Math.min(nanos, TimeUnit.SECONDS.toNanos(1));
    }

    @SuppressForbidden(reason = "JFR")
    @StackTrace(false)
    public static class HistogramEvent extends Event {

        @SuppressForbidden(reason = "JFR")
        @Label("Name")
        public String name;

        @SuppressForbidden(reason = "JFR")
        @Label("10%")
        public long _10;

        @SuppressForbidden(reason = "JFR")
        @Label("50%")
        public long _50;

        @SuppressForbidden(reason = "JFR")
        @Label("90%")
        public long _90;

        @SuppressForbidden(reason = "JFR")
        @Label("99%")
        public long _99;

        @SuppressForbidden(reason = "JFR")
        @Label("99.9%")
        public long _99_9;

        @SuppressForbidden(reason = "JFR")
        @Label("99.99%")
        public long _99_99;

        @SuppressForbidden(reason = "JFR")
        @Label("99.999%")
        public long _99_999;

        @SuppressForbidden(reason = "JFR")
        @Label("Max")
        public long max;

        @SuppressForbidden(reason = "JFR")
        @Label("Mean")
        public double mean;

        @SuppressForbidden(reason = "JFR")
        @Label("Total")
        public long total;

    }

    @SuppressForbidden(reason = "JFR")
    @Name(IntervalHistogramEvent.NAME)
    @Label("Interval Histogram")
    @Category("Elasticsearch")
    public static class IntervalHistogramEvent extends HistogramEvent {

        static final String NAME = "org.elasticsearch.jfr.IntervalHistogramEvent";

    }

    @SuppressForbidden(reason = "JFR")
    @Name(TotalHistogramEvent.NAME)
    @Label("Total Histogram")
    @Category("Elasticsearch")
    @StackTrace(false)
    public static class TotalHistogramEvent extends HistogramEvent {

        static final String NAME = "org.elasticsearch.jfr.TotalHistogramEvent";

    }

    @SuppressForbidden(reason = "JFR")
    @Name(MeanMetricEvent.NAME)
    @Label("Mean Metric")
    @Category("Elasticsearch")
    @StackTrace(false)
    public static class MeanMetricEvent extends Event {

        static final String NAME = "org.elasticsearch.jfr.MeanMetricEvent";

        @SuppressForbidden(reason = "JFR")
        @Label("Name")
        public String name;

        @SuppressForbidden(reason = "JFR")
        @Label("Mean")
        public double mean;

        @SuppressForbidden(reason = "JFR")
        @Label("Counter")
        public long counter;

        @SuppressForbidden(reason = "JFR")
        @Label("Sum")
        public long sum;

    }
}
