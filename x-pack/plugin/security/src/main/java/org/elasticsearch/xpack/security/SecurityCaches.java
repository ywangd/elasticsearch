/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.CheckedRunnable;
import org.elasticsearch.common.cache.Cache;
import org.elasticsearch.common.cache.RemovalListener;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.common.util.concurrent.FutureUtils;
import org.elasticsearch.common.util.concurrent.ListenableFuture;
import org.elasticsearch.common.util.concurrent.ReleasableLock;
import org.elasticsearch.xpack.security.support.SecurityIndexManager;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.elasticsearch.xpack.security.support.SecurityIndexManager.isIndexDeleted;
import static org.elasticsearch.xpack.security.support.SecurityIndexManager.isMoveFromRedToNonRed;

// A few requirements to satisfy
//  * Direct or Listenable future
//  * Arbitrary Key/Value types
//  * Primary and Secondary caches for caching and invalidation
//  * Minimize stale result possibility
//  * Convenient API support
//  * Centralised security index change support

public class SecurityCaches {

    private static final Map<String, Tuple<Consumer<Collection<String>>, Runnable>> cacheInvalidationCallbacks = new ConcurrentHashMap<>();

    public static <V> DirectSecurityCache<V> newSecurityCache(String name, Cache<String, V> delegate) {
        return newSecurityCache(name, delegate, null);
    }

    public static <V> DirectSecurityCache<V> newSecurityCache(
        String name,
        Cache<String, V> delegate,
        CacheInvalidator extraCacheInvalidator) {
        if (cacheInvalidationCallbacks.containsKey(name)) {
            // throw new IllegalArgumentException("Security cache of name [" + name + "] already exists");
        }
        final DirectSecurityCache<V> securityCache = new DirectSecurityCache<>(name, delegate, extraCacheInvalidator);
        cacheInvalidationCallbacks.put(name, new Tuple<>(securityCache::invalidate, securityCache::invalidateAll));
        return securityCache;
    }

    public static void onSecurityIndexStageChange(SecurityIndexManager.State previousState, SecurityIndexManager.State currentState) {
        if (isMoveFromRedToNonRed(previousState, currentState) || isIndexDeleted(previousState,
            currentState) || previousState.isIndexUpToDate != currentState.isIndexUpToDate) {
            cacheInvalidationCallbacks.values().stream().map(Tuple::v2).forEach(Runnable::run);
        }
    }

    // TODO: The static invalidation methods can be used to implement APIs for clearing named security caches:
    //       e.g. /_security/_cache/{name}/_clear_cache
    public static void invalidate(String name, Collection<String> keys) {
        final Consumer<Collection<String>> consumer = cacheInvalidationCallbacks.get(name).v1();
        if (consumer != null) {
            consumer.accept(keys);
        }
    }

    public static void invalidateAll(String name) {
        final Runnable callback = cacheInvalidationCallbacks.get(name).v2();
        if (callback != null) {
            callback.run();
        }
    }

    public static class DirectSecurityCache<V> {

        private static final Logger logger = LogManager.getLogger(DirectSecurityCache.class);

        private final String name;
        private final Cache<String, V> delegate;
        private final CacheInvalidator extraCacheInvalidator;
        private final AtomicLong numInvalidation = new AtomicLong();
        private final ReadWriteLock invalidationLock = new ReentrantReadWriteLock();
        private final ReleasableLock invalidationReadLock = new ReleasableLock(invalidationLock.readLock());
        private final ReleasableLock invalidationWriteLock = new ReleasableLock(invalidationLock.writeLock());

        private DirectSecurityCache(String name, Cache<String, V> delegate, CacheInvalidator extraCacheInvalidator) {
            this.name = name;
            this.delegate = delegate;
            this.extraCacheInvalidator = extraCacheInvalidator;
        }

        public CacheItemsConsumer<V> preparePut() {
            final long invalidationCounter = numInvalidation.get();
            return (key, value, extraCachingRunnable) -> {
                try (ReleasableLock ignored = invalidationReadLock.acquire()) {
                    if (invalidationCounter == numInvalidation.get()) {
                        logger.debug("Cache: [{}] - caching key [{}]", name, key);
                        delegate.put(key, value);
                        if (extraCachingRunnable != null) {
                            try {
                                extraCachingRunnable.run();
                            } catch (Exception e) {
                                logger.error("Failed to cache extra item for cache [" + name + "]", e);
                            }
                        }
                    }
                }
            };
        }

        public V get(String key) {
            // It is possible that item is available in the main cache, but not yet placed into the secondary caches
            return delegate.get(key);
        }

        public void invalidate(Collection<String> keys) {
            try (ReleasableLock ignored = invalidationWriteLock.acquire()) {
                numInvalidation.incrementAndGet();
            }
            logger.debug("Cache: [{}] - invalidating [{}]", name, keys);
            keys.forEach(delegate::invalidate);
            if (extraCacheInvalidator != null) {
                extraCacheInvalidator.invalidate(keys);
            }
        }

        public void invalidateAll() {
            try (ReleasableLock ignored = invalidationWriteLock.acquire()) {
                numInvalidation.incrementAndGet();
            }
            logger.debug("Cache: [{}] - invalidating all", name);
            delegate.invalidateAll();
            if (extraCacheInvalidator != null) {
                extraCacheInvalidator.invalidate(null);
            }
        }
    }

    public static class ListenableSecurityCache<K, V, T> {

        private static final Logger logger = LogManager.getLogger(DirectSecurityCache.class);

        private final String name;
        private final Cache<K, ListenableFuture<V>> delegate;
        private final List<SecondaryCache<K, V, T>> secondaryCaches;
        private final AtomicLong numInvalidation = new AtomicLong();
        private final ReadWriteLock invalidationLock = new ReentrantReadWriteLock();
        private final ReleasableLock invalidationReadLock = new ReleasableLock(invalidationLock.readLock());
        private final ReleasableLock invalidationWriteLock = new ReleasableLock(invalidationLock.writeLock());

        public ListenableSecurityCache(
            String name,
            Function<RemovalListener<K, ListenableFuture<V>>, Cache<K, ListenableFuture<V>>> cacheBuilder) {
            this(name, cacheBuilder, List.of());
        }

        private ListenableSecurityCache(
            String name,
            Function<RemovalListener<K, ListenableFuture<V>>, Cache<K, ListenableFuture<V>>> cacheBuilder,
            List<SecondaryCache<K, V, T>> secondaryCaches) {
            this.name = name;
            this.secondaryCaches = secondaryCaches;
            if (secondaryCaches.isEmpty()) {
                this.delegate = cacheBuilder.apply(null);
            } else {
                this.delegate = cacheBuilder.apply(notification -> {
                    try {
                        final V value = FutureUtils.get(notification.getValue(), 0L, TimeUnit.NANOSECONDS);
                        secondaryCaches.forEach(c -> c.invalidate(List.of(new Tuple<>(notification.getKey(), value))));
                    } catch (Exception e) {
                        logger.error("Cannot get value to invalidate", e);
                    }
                });
            }
        }

        public Tuple<ListenableFuture<V>, Boolean> get(
            K key,
            BiConsumer<K, ActionListener<T>> getter,
            Function<T, V> transform) throws ExecutionException {

            final long invalidationCounter = numInvalidation.get();
            final AtomicBoolean valueAlreadyInCache = new AtomicBoolean(true);
            final ListenableFuture<V> listenableFuture = delegate.computeIfAbsent(key, k -> {
                valueAlreadyInCache.set(false);
                return new ListenableFuture<>();
            });
            // First one to retrieve
            if (false == valueAlreadyInCache.get()) {
                listenableFuture.addListener(new ActionListener<V>() {
                    @Override
                    public void onResponse(V v) {
                        try (ReleasableLock ignored = invalidationReadLock.acquire()) {
                            if (invalidationCounter == numInvalidation.get()) {
                                logger.debug("Cache: [{}] - caching key [{}]", name, key);
                            } else {
                                delegate.invalidate(key, listenableFuture);
                            }
                        }
                    }
                    @Override
                    public void onFailure(Exception e) {
                        delegate.invalidate(key, listenableFuture);
                    }
                }, EsExecutors.newDirectExecutorService());
                getter.accept(key, new ActionListener<T>() {
                    @Override
                    public void onResponse(T response) {
                        final V value = transform.apply(response);
                        listenableFuture.onResponse(value);
                        secondaryCaches.forEach(c -> c.cache(new Tuple<>(key, value), response));
                    }

                    @Override
                    public void onFailure(Exception e) {
                        delegate.invalidate(key, listenableFuture);
                    }
                });

            }
            return new Tuple<>(listenableFuture, valueAlreadyInCache.get());
        }

        public void invalidate(Collection<K> keys) {
            try (ReleasableLock ignored = invalidationWriteLock.acquire()) {
                numInvalidation.incrementAndGet();
            }
            logger.debug("Cache: [{}] - invalidating [{}]", name, keys);
            keys.forEach(delegate::invalidate);
        }

        public void invalidateAll() {
            try (ReleasableLock ignored = invalidationWriteLock.acquire()) {
                numInvalidation.incrementAndGet();
            }
            logger.debug("Cache: [{}] - invalidating all", name);
            delegate.invalidateAll();
        }
    }

    public interface CacheItemsConsumer<V> {
        void consume(String key, V value, CheckedRunnable<Exception> extraCachingRunnable);

        default void consume(String key, V value) {
            consume(key, value, null);
        }
    }

    public interface CacheInvalidator {
        void invalidate(Collection<String> keys);
    }

    public interface SecondaryCache<K, V, T> {
        void cache(Tuple<K, V> primaryItem, T originalValue);
        void invalidate(Collection<Tuple<K, V>> primaryItems);
        void invalidateAll();
    }
}
