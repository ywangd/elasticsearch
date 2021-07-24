/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.metric;

import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ToXContentFragment;
import org.elasticsearch.common.xcontent.XContentBuilder;

import java.io.IOException;

public class HistogramMetric implements Writeable, ToXContentFragment {

    InstrumentedMethod method;
    long count;
    long min;
    long max;
    long mean;
    long pct_10;
    long pct_50;
    long pct_90;
    long pct_99;

    public HistogramMetric(InstrumentedMethod method) {
        this.method = method;
    }

    public HistogramMetric(
        InstrumentedMethod method,
        long count,
        long min,
        long max,
        long mean,
        long pct_10,
        long pct_50,
        long pct_90,
        long pct_99
    ) {
        this.method = method;
        this.count = count;
        this.min = min;
        this.max = max;
        this.mean = mean;
        this.pct_10 = pct_10;
        this.pct_50 = pct_50;
        this.pct_90 = pct_90;
        this.pct_99 = pct_99;
    }

    public HistogramMetric(StreamInput in) throws IOException {
        this.method = in.readEnum(InstrumentedMethod.class);
        this.count = in.readLong();
        this.min = in.readLong();
        this.max = in.readLong();
        this.mean = in.readLong();
        this.pct_10 = in.readLong();
        this.pct_50 = in.readLong();
        this.pct_90 = in.readLong();
        this.pct_99 = in.readLong();
    }

    public boolean isZero() {
        return count == 0;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(method);
        out.writeLong(count);
        out.writeLong(min);
        out.writeLong(max);
        out.writeLong(mean);
        out.writeLong(pct_10);
        out.writeLong(pct_50);
        out.writeLong(pct_90);
        out.writeLong(pct_99);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject(method.jsonName())
            .field("count", count)
            .field("min", min)
            .field("max", max)
            .field("mean", mean)
            .field("pct_10", pct_10)
            .field("pct_50", pct_50)
            .field("pct_90", pct_90)
            .field("pct_99", pct_99)
            .endObject();
    }

    public static HistogramMetric empty(InstrumentedMethod method) {
        return new HistogramMetric(method);
    }
}
