/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.repositories.s3;

import com.amazonaws.AmazonClientException;
import com.amazonaws.Request;
import com.amazonaws.Response;
import com.amazonaws.metrics.RequestMetricCollector;
import com.amazonaws.services.s3.model.CannedAccessControlList;
import com.amazonaws.services.s3.model.DeleteObjectsRequest;
import com.amazonaws.services.s3.model.MultiObjectDeleteException;
import com.amazonaws.services.s3.model.StorageClass;
import com.amazonaws.util.AWSRequestMetrics;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.cluster.metadata.RepositoryMetadata;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.blobstore.BlobContainer;
import org.elasticsearch.common.blobstore.BlobPath;
import org.elasticsearch.common.blobstore.BlobStore;
import org.elasticsearch.common.blobstore.BlobStoreException;
import org.elasticsearch.common.blobstore.OperationPurpose;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.telemetry.metric.Meter;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.elasticsearch.core.Strings.format;

class S3BlobStore implements BlobStore {

    /**
     * Maximum number of deletes in a {@link DeleteObjectsRequest}.
     * @see <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/multiobjectdeleteapi.html">S3 Documentation</a>.
     */
    private static final int MAX_BULK_DELETES = 1000;

    private static final Logger logger = LogManager.getLogger(S3BlobStore.class);

    private final S3Service service;

    private final BigArrays bigArrays;

    private final String bucket;

    private final ByteSizeValue bufferSize;

    private final boolean serverSideEncryption;

    private final CannedAccessControlList cannedACL;

    private final StorageClass storageClass;

    private final RepositoryMetadata repositoryMetadata;

    private final ThreadPool threadPool;
    private final Executor snapshotExecutor;
    private final Meter meter;

    private final Stats stats = new Stats();

    final RequestMetricCollector getMetricCollector;
    final RequestMetricCollector listMetricCollector;
    final RequestMetricCollector putMetricCollector;
    final RequestMetricCollector multiPartUploadMetricCollector;
    final RequestMetricCollector deleteMetricCollector;
    final RequestMetricCollector abortPartUploadMetricCollector;

    S3BlobStore(
        S3Service service,
        String bucket,
        boolean serverSideEncryption,
        ByteSizeValue bufferSize,
        String cannedACL,
        String storageClass,
        RepositoryMetadata repositoryMetadata,
        BigArrays bigArrays,
        ThreadPool threadPool,
        Meter meter
    ) {
        this.service = service;
        this.bigArrays = bigArrays;
        this.bucket = bucket;
        this.serverSideEncryption = serverSideEncryption;
        this.bufferSize = bufferSize;
        this.cannedACL = initCannedACL(cannedACL);
        this.storageClass = initStorageClass(storageClass);
        this.repositoryMetadata = repositoryMetadata;
        this.threadPool = threadPool;
        this.snapshotExecutor = threadPool.executor(ThreadPool.Names.SNAPSHOT);
        this.meter = meter;

        Stream.of("GetObject", "ListObjects", "PutObject", "PutMultipartObject", "DeleteObjects", "AbortMultipartObject")
            .forEach(operation -> {
                this.meter.registerLongCounter("request_counter/" + operation, "request count counter", "unit");
                this.meter.registerLongGauge("request_gauge/" + operation, "request count gauge", "unit");
                this.meter.registerLongHistogram("request_histogram/" + operation, "request count histogram", "unit");
            });

        this.getMetricCollector = new IgnoreNoResponseMetricsCollector() {
            @Override
            public void collectMetrics(Request<?> request) {
                assert request.getHttpMethod().name().equals("GET");
                final long requestCount = getRequestCount(request);
                meter.getLongCounter("request_counter/GetObject").incrementBy(requestCount, Map.of("operation", "GetObject"));
                meter.getLongGauge("request_gauge/GetObject").record(requestCount, Map.of("operation", "GetObject"));
                meter.getLongHistogram("request_histogram/GetObject").record(requestCount, Map.of("operation", "GetObject"));
                stats.getCount.addAndGet(requestCount);
            }
        };
        this.listMetricCollector = new IgnoreNoResponseMetricsCollector() {
            @Override
            public void collectMetrics(Request<?> request) {
                assert request.getHttpMethod().name().equals("GET");
                final long requestCount = getRequestCount(request);
                meter.getLongCounter("request_counter/ListObjects").incrementBy(requestCount, Map.of("operation", "ListObjects"));
                meter.getLongGauge("request_gauge/ListObjects").record(requestCount, Map.of("operation", "ListObjects"));
                meter.getLongHistogram("request_histogram/ListObjects").record(requestCount, Map.of("operation", "ListObjects"));
                stats.listCount.addAndGet(requestCount);
            }
        };
        this.putMetricCollector = new IgnoreNoResponseMetricsCollector() {
            @Override
            public void collectMetrics(Request<?> request) {
                assert request.getHttpMethod().name().equals("PUT");
                final long requestCount = getRequestCount(request);
                meter.getLongCounter("request_counter/PutObject").incrementBy(requestCount, Map.of("operation", "PutObject"));
                meter.getLongGauge("request_gauge/PutObject").record(requestCount, Map.of("operation", "PutObject"));
                meter.getLongHistogram("request_histogram/PutObject").record(requestCount, Map.of("operation", "PutObject"));
                stats.putCount.addAndGet(requestCount);
            }
        };
        this.multiPartUploadMetricCollector = new IgnoreNoResponseMetricsCollector() {
            @Override
            public void collectMetrics(Request<?> request) {
                assert request.getHttpMethod().name().equals("PUT") || request.getHttpMethod().name().equals("POST");
                final long requestCount = getRequestCount(request);
                meter.getLongCounter("request_counter/PutMultipartObject")
                    .incrementBy(requestCount, Map.of("operation", "PutMultipartObject"));
                meter.getLongGauge("request_gauge/PutMultipartObject").record(requestCount, Map.of("operation", "PutMultipartObject"));
                meter.getLongHistogram("request_histogram/PutMultipartObject")
                    .record(requestCount, Map.of("operation", "PutMultipartObject"));
                stats.postCount.addAndGet(requestCount);
            }
        };
        this.deleteMetricCollector = new IgnoreNoResponseMetricsCollector() {
            @Override
            public void collectMetrics(Request<?> request) {
                assert request.getHttpMethod().name().equals("POST");
                final long requestCount = getRequestCount(request);
                meter.getLongCounter("request_counter/DeleteObjects").incrementBy(requestCount, Map.of("operation", "DeleteObjects"));
                meter.getLongGauge("request_gauge/DeleteObjects").record(requestCount, Map.of("operation", "DeleteObjects"));
                meter.getLongHistogram("request_histogram/DeleteObjects").record(requestCount, Map.of("operation", "DeleteObjects"));
                stats.deleteCount.addAndGet(requestCount);
            }
        };
        this.abortPartUploadMetricCollector = new IgnoreNoResponseMetricsCollector() {
            @Override
            public void collectMetrics(Request<?> request) {
                assert request.getHttpMethod().name().equals("DELETE");
                final long requestCount = getRequestCount(request);
                meter.getLongCounter("request_counter/AbortMultipartObject")
                    .incrementBy(requestCount, Map.of("operation", "AbortMultipartObject"));
                meter.getLongGauge("request_gauge/AbortMultipartObject").record(requestCount, Map.of("operation", "AbortMultipartObject"));
                meter.getLongHistogram("request_histogram/AbortMultipartObject")
                    .record(requestCount, Map.of("operation", "AbortMultipartObject"));
                stats.abortCount.addAndGet(requestCount);
            }
        };
    }

    public Executor getSnapshotExecutor() {
        return snapshotExecutor;
    }

    public TimeValue getCompareAndExchangeTimeToLive() {
        return service.compareAndExchangeTimeToLive;
    }

    // metrics collector that ignores null responses that we interpret as the request not reaching the S3 endpoint due to a network
    // issue
    private abstract static class IgnoreNoResponseMetricsCollector extends RequestMetricCollector {

        @Override
        public final void collectMetrics(Request<?> request, Response<?> response) {
            if (response != null) {
                collectMetrics(request);
            }
        }

        protected abstract void collectMetrics(Request<?> request);
    }

    private long getRequestCount(Request<?> request) {
        Number requestCount = request.getAWSRequestMetrics().getTimingInfo().getCounter(AWSRequestMetrics.Field.RequestCount.name());
        if (requestCount == null) {
            logger.warn("Expected request count to be tracked for request [{}] but found not count.", request);
            return 0L;
        }
        return requestCount.longValue();
    }

    @Override
    public String toString() {
        return bucket;
    }

    public AmazonS3Reference clientReference() {
        return service.client(repositoryMetadata);
    }

    int getMaxRetries() {
        return service.settings(repositoryMetadata).maxRetries;
    }

    public String bucket() {
        return bucket;
    }

    public BigArrays bigArrays() {
        return bigArrays;
    }

    public boolean serverSideEncryption() {
        return serverSideEncryption;
    }

    public long bufferSizeInBytes() {
        return bufferSize.getBytes();
    }

    @Override
    public BlobContainer blobContainer(BlobPath path) {
        return new S3BlobContainer(path, this);
    }

    @Override
    public void deleteBlobsIgnoringIfNotExists(OperationPurpose purpose, Iterator<String> blobNames) throws IOException {
        if (blobNames.hasNext() == false) {
            return;
        }

        final List<String> partition = new ArrayList<>();
        try (AmazonS3Reference clientReference = clientReference()) {
            // S3 API only allows 1k blobs per delete so we split up the given blobs into requests of max. 1k deletes
            final AtomicReference<Exception> aex = new AtomicReference<>();
            SocketAccess.doPrivilegedVoid(() -> {
                blobNames.forEachRemaining(key -> {
                    partition.add(key);
                    if (partition.size() == MAX_BULK_DELETES) {
                        deletePartition(purpose, clientReference, partition, aex);
                        partition.clear();
                    }
                });
                if (partition.isEmpty() == false) {
                    deletePartition(purpose, clientReference, partition, aex);
                }
            });
            if (aex.get() != null) {
                throw aex.get();
            }
        } catch (Exception e) {
            throw new IOException("Failed to delete blobs " + partition.stream().limit(10).toList(), e);
        }
    }

    private void deletePartition(
        OperationPurpose purpose,
        AmazonS3Reference clientReference,
        List<String> partition,
        AtomicReference<Exception> aex
    ) {
        try {
            clientReference.client().deleteObjects(bulkDelete(purpose, this, partition));
        } catch (MultiObjectDeleteException e) {
            // We are sending quiet mode requests so we can't use the deleted keys entry on the exception and instead
            // first remove all keys that were sent in the request and then add back those that ran into an exception.
            logger.warn(
                () -> format(
                    "Failed to delete some blobs %s",
                    e.getErrors().stream().map(err -> "[" + err.getKey() + "][" + err.getCode() + "][" + err.getMessage() + "]").toList()
                ),
                e
            );
            aex.set(ExceptionsHelper.useOrSuppress(aex.get(), e));
        } catch (AmazonClientException e) {
            // The AWS client threw any unexpected exception and did not execute the request at all so we do not
            // remove any keys from the outstanding deletes set.
            aex.set(ExceptionsHelper.useOrSuppress(aex.get(), e));
        }
    }

    private static DeleteObjectsRequest bulkDelete(OperationPurpose purpose, S3BlobStore blobStore, List<String> blobs) {
        return new DeleteObjectsRequest(blobStore.bucket()).withKeys(blobs.toArray(Strings.EMPTY_ARRAY))
            .withQuiet(true)
            .withRequestMetricCollector(blobStore.deleteMetricCollector);
    }

    @Override
    public void close() throws IOException {
        this.service.close();
    }

    @Override
    public Map<String, Long> stats() {
        return stats.toMap();
    }

    public CannedAccessControlList getCannedACL() {
        return cannedACL;
    }

    public StorageClass getStorageClass() {
        return storageClass;
    }

    public static StorageClass initStorageClass(String storageClass) {
        if ((storageClass == null) || storageClass.equals("")) {
            return StorageClass.Standard;
        }

        try {
            final StorageClass _storageClass = StorageClass.fromValue(storageClass.toUpperCase(Locale.ENGLISH));
            if (_storageClass.equals(StorageClass.Glacier)) {
                throw new BlobStoreException("Glacier storage class is not supported");
            }

            return _storageClass;
        } catch (final IllegalArgumentException illegalArgumentException) {
            throw new BlobStoreException("`" + storageClass + "` is not a valid S3 Storage Class.");
        }
    }

    /**
     * Constructs canned acl from string
     */
    public static CannedAccessControlList initCannedACL(String cannedACL) {
        if ((cannedACL == null) || cannedACL.equals("")) {
            return CannedAccessControlList.Private;
        }

        for (final CannedAccessControlList cur : CannedAccessControlList.values()) {
            if (cur.toString().equalsIgnoreCase(cannedACL)) {
                return cur;
            }
        }

        throw new BlobStoreException("cannedACL is not valid: [" + cannedACL + "]");
    }

    ThreadPool getThreadPool() {
        return threadPool;
    }

    static class Stats {

        final AtomicLong listCount = new AtomicLong();

        final AtomicLong getCount = new AtomicLong();

        final AtomicLong putCount = new AtomicLong();

        final AtomicLong postCount = new AtomicLong();

        final AtomicLong deleteCount = new AtomicLong();

        final AtomicLong abortCount = new AtomicLong();

        Map<String, Long> toMap() {
            final Map<String, Long> results = new HashMap<>();
            results.put("GetObject", getCount.get());
            results.put("ListObjects", listCount.get());
            results.put("PutObject", putCount.get());
            results.put("PutMultipartObject", postCount.get());
            results.put("DeleteObjects", deleteCount.get());
            results.put("AbortMultipartObject", abortCount.get());
            return results;
        }
    }
}
