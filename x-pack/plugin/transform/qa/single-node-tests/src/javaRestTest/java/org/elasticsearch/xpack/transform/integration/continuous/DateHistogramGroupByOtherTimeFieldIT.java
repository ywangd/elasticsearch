package org.elasticsearch.xpack.transform.integration.continuous;

import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.client.transform.transforms.DestConfig;
import org.elasticsearch.client.transform.transforms.SourceConfig;
import org.elasticsearch.client.transform.transforms.TransformConfig;
import org.elasticsearch.client.transform.transforms.pivot.DateHistogramGroupSource;
import org.elasticsearch.client.transform.transforms.pivot.GroupConfig;
import org.elasticsearch.client.transform.transforms.pivot.PivotConfig;
import org.elasticsearch.client.transform.transforms.pivot.TermsGroupSource;
import org.elasticsearch.common.xcontent.support.XContentMapValues;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.aggregations.AggregatorFactories;
import org.elasticsearch.search.aggregations.BucketOrder;
import org.elasticsearch.search.aggregations.bucket.histogram.DateHistogramAggregationBuilder;
import org.elasticsearch.search.aggregations.bucket.histogram.DateHistogramInterval;
import org.elasticsearch.search.aggregations.bucket.histogram.Histogram;
import org.elasticsearch.search.aggregations.bucket.histogram.Histogram.Bucket;
import org.elasticsearch.search.aggregations.bucket.terms.Terms;
import org.elasticsearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.elasticsearch.search.builder.SearchSourceBuilder;

import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;

/**
 * Testcase for date histogram group_by on _different_ fields than used for sync
 */
public class DateHistogramGroupByOtherTimeFieldIT extends ContinuousTestCase {
    private static final String NAME = "continuous-date-histogram-pivot-other-timefield-test";

    private final boolean addGroupByTerms;

    public DateHistogramGroupByOtherTimeFieldIT() {
        addGroupByTerms = randomBoolean();
    }

    @Override
    public TransformConfig createConfig() {
        TransformConfig.Builder transformConfigBuilder = new TransformConfig.Builder();
        addCommonBuilderParameters(transformConfigBuilder);
        transformConfigBuilder.setSource(new SourceConfig(CONTINUOUS_EVENTS_SOURCE_INDEX));
        transformConfigBuilder.setDest(new DestConfig(NAME, INGEST_PIPELINE));
        transformConfigBuilder.setId(NAME);
        PivotConfig.Builder pivotConfigBuilder = new PivotConfig.Builder();
        GroupConfig.Builder groups = new GroupConfig.Builder().groupBy(
            "second",
            new DateHistogramGroupSource.Builder().setField("metric-timestamp")
                .setInterval(new DateHistogramGroupSource.FixedInterval(DateHistogramInterval.SECOND))
                .build()
        );
        if (addGroupByTerms) {
            groups.groupBy("event", new TermsGroupSource.Builder().setField("event").build());
        }
        pivotConfigBuilder.setGroups(groups.build());
        AggregatorFactories.Builder aggregations = new AggregatorFactories.Builder();
        addCommonAggregations(aggregations);

        pivotConfigBuilder.setAggregations(aggregations);
        transformConfigBuilder.setPivotConfig(pivotConfigBuilder.build());
        return transformConfigBuilder.build();
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void testIteration(int iteration) throws IOException {
        SearchRequest searchRequestSource = new SearchRequest(CONTINUOUS_EVENTS_SOURCE_INDEX).allowPartialSearchResults(false)
            .indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN);
        SearchSourceBuilder sourceBuilderSource = new SearchSourceBuilder().size(0);
        DateHistogramAggregationBuilder bySecond = new DateHistogramAggregationBuilder("second").field("metric-timestamp")
            .fixedInterval(DateHistogramInterval.SECOND)
            .order(BucketOrder.key(true));

        if (addGroupByTerms) {
            TermsAggregationBuilder terms = new TermsAggregationBuilder("event").size(1000).field("event").order(BucketOrder.key(true));
            bySecond.subAggregation(terms);
        }
        sourceBuilderSource.aggregation(bySecond);
        searchRequestSource.source(sourceBuilderSource);
        SearchResponse responseSource = search(searchRequestSource);

        SearchRequest searchRequestDest = new SearchRequest(NAME).allowPartialSearchResults(false)
            .indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN);
        SearchSourceBuilder sourceBuilderDest = new SearchSourceBuilder().size(10000).sort("second");
        if (addGroupByTerms) {
            sourceBuilderDest.sort("event");
        }

        searchRequestDest.source(sourceBuilderDest);
        SearchResponse responseDest = search(searchRequestDest);

        if (addGroupByTerms) {
            assertResultsGroupByDateHistogramAndTerms(iteration, responseSource, responseDest);
        } else {
            assertResultsGroupByDateHistogram(iteration, responseSource, responseDest);
        }
    }

    private void assertResultsGroupByDateHistogram(int iteration, SearchResponse responseSource, SearchResponse responseDest) {
        List<? extends Bucket> buckets = ((Histogram) responseSource.getAggregations().get("second")).getBuckets();
        Iterator<? extends Bucket> sourceIterator = buckets.iterator();
        Iterator<SearchHit> destIterator = responseDest.getHits().iterator();

        while (sourceIterator.hasNext() && destIterator.hasNext()) {
            Bucket bucket = sourceIterator.next();
            SearchHit searchHit = destIterator.next();
            Map<String, Object> source = searchHit.getSourceAsMap();

            Long transformBucketKey = (Long) XContentMapValues.extractValue("second", source);

            // aggs return buckets with 0 doc_count while composite aggs skip over them
            while (bucket.getDocCount() == 0L) {
                assertTrue(sourceIterator.hasNext());
                bucket = sourceIterator.next();
            }
            long bucketKey = ((ZonedDateTime) bucket.getKey()).toEpochSecond() * 1000;

            // test correctness, the results from the aggregation and the results from the transform should be the same
            assertThat(
                "Buckets did not match, source: " + source + ", expected: " + bucketKey + ", iteration: " + iteration,
                transformBucketKey,
                equalTo(bucketKey)
            );
            assertThat(
                "Doc count did not match, source: " + source + ", expected: " + bucket.getDocCount() + ", iteration: " + iteration,
                ((Integer) XContentMapValues.extractValue("count", source)).longValue(),
                equalTo(bucket.getDocCount())
            );

            // transform should only rewrite documents that require it
            assertThat(
                "Ingest run: "
                    + XContentMapValues.extractValue(INGEST_RUN_FIELD, source)
                    + " did not match max run: "
                    + XContentMapValues.extractValue(MAX_RUN_FIELD, source)
                    + ", iteration: "
                    + iteration,
                // we use a fixed_interval of `1s`, the transform runs every `1s`, a bucket might be recalculated at the next run
                // but should NOT be recalculated for the 2nd/3rd/... run
                (Integer) XContentMapValues.extractValue(INGEST_RUN_FIELD, source) - (Integer) XContentMapValues.extractValue(
                    MAX_RUN_FIELD,
                    source
                ),
                is(lessThanOrEqualTo(1))
            );

        }
        assertFalse(sourceIterator.hasNext());
        assertFalse(destIterator.hasNext());
    }

    private void assertResultsGroupByDateHistogramAndTerms(int iteration, SearchResponse responseSource, SearchResponse responseDest) {
        List<? extends Bucket> buckets = ((Histogram) responseSource.getAggregations().get("second")).getBuckets();

        List<Map<String, Object>> flattenedBuckets = new ArrayList<>();
        for (Bucket b : buckets) {
            if (b.getDocCount() == 0) {
                continue;
            }
            long second = ((ZonedDateTime) b.getKey()).toEpochSecond() * 1000;
            List<? extends Terms.Bucket> terms = ((Terms) b.getAggregations().get("event")).getBuckets();
            for (Terms.Bucket t : terms) {
                flattenedBuckets.add(flattenedResult(second, t.getKeyAsString(), t.getDocCount()));
            }
        }

        Iterator<Map<String, Object>> sourceIterator = flattenedBuckets.iterator();
        Iterator<SearchHit> destIterator = responseDest.getHits().iterator();

        while (sourceIterator.hasNext() && destIterator.hasNext()) {
            Map<String, Object> bucket = sourceIterator.next();

            SearchHit searchHit = destIterator.next();
            Map<String, Object> source = searchHit.getSourceAsMap();

            Long transformBucketKey = (Long) XContentMapValues.extractValue("second", source);

            // test correctness, the results from the aggregation and the results from the transform should be the same
            assertThat(
                "Buckets did not match, source: " + source + ", expected: " + bucket.get("second") + ", iteration: " + iteration,
                transformBucketKey,
                equalTo(bucket.get("second"))
            );
            assertThat(
                "Doc count did not match, source: " + source + ", expected: " + bucket.get("count") + ", iteration: " + iteration,
                ((Integer) XContentMapValues.extractValue("count", source)).longValue(),
                equalTo(bucket.get("count"))
            );
            assertThat(
                "Term did not match, source: " + source + ", expected: " + bucket.get("event") + ", iteration: " + iteration,
                XContentMapValues.extractValue("event", source),
                equalTo(bucket.get("event"))
            );

            // transform should only rewrite documents that require it
            assertThat(
                "Ingest run: "
                    + XContentMapValues.extractValue(INGEST_RUN_FIELD, source)
                    + " did not match max run: "
                    + XContentMapValues.extractValue(MAX_RUN_FIELD, source)
                    + ", iteration: "
                    + iteration,
                // we use a fixed_interval of `1s`, the transform runs every `1s`, a bucket might be recalculated at the next run
                // but should NOT be recalculated for the 2nd/3rd/... run
                (Integer) XContentMapValues.extractValue(INGEST_RUN_FIELD, source) - (Integer) XContentMapValues.extractValue(
                    MAX_RUN_FIELD,
                    source
                ),
                is(lessThanOrEqualTo(2))
            );
        }
        assertFalse(sourceIterator.hasNext());
        assertFalse(destIterator.hasNext());
    }

    private static Map<String, Object> flattenedResult(long second, String event, long count) {
        Map<String, Object> doc = new HashMap<>();
        doc.put("second", second);
        doc.put("event", event);
        doc.put("count", count);
        return doc;
    }
}
