/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.PlainActionFuture;
import org.elasticsearch.common.cache.Cache;
import org.elasticsearch.common.cache.RemovalListener;
import org.elasticsearch.common.collect.Tuple;
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
import java.util.stream.Collectors;

import static org.elasticsearch.xpack.security.support.SecurityIndexManager.isIndexDeleted;
import static org.elasticsearch.xpack.security.support.SecurityIndexManager.isMoveFromRedToNonRed;

// A few requirements to satisfy
//  * Direct or Listenable future
//  * Arbitrary Key/Value types
//  * Primary and Secondary caches for caching and invalidation
//  * Minimize stale result possibility
//  * Convenient API support
//  * Centralised security index change support
//  * The primary cache may cache value differently than what is directly fetched (need transform).
//    The transform may break a single key/value into several key/value pairs to cache.
//    However the main logic of the program still needs the un-transformed value. This is important
//    as it guarantees that once value is fetched, the program will progress. Otherwise, if the primary
//    cached value is returned but secondary cache misses, it could potentially lead infinite loop.
//  * The primary cache may not want fetch value immediately on cache miss since we may wanna group
//    multiple fetch (for multiple keys)

public class SecurityCaches {

    private static final Map<String, StringKeyedInvalidatable> cacheInvalidationCallbacks = new ConcurrentHashMap<>();

    public static <K, V, R> DirectSecurityCache<K, V, R> newDirectSecurityCache(
        String name,
        Function<RemovalListener<K, V>, Cache<K, V>> cacheBuilder,
        Function<DirectSecurityCache<K, V, R>, StringKeyedInvalidatable> cacheInvalidatorBuilder,
        List<SecondaryCache<K, V, R>> secondaryCaches) {

        assert false == cacheInvalidationCallbacks.containsKey(name) : "Security cache of name [" + name + "] already exists";
        final DirectSecurityCache<K, V, R> securityCache = new DirectSecurityCache<>(name, cacheBuilder, secondaryCaches);
        cacheInvalidationCallbacks.put(name, cacheInvalidatorBuilder.apply(securityCache));
        return securityCache;
    }

    public static <K, V, R> ListenableSecurityCache<K, V, R> newListenableSecurityCache(
        String name,
        Function<RemovalListener<K, ListenableFuture<V>>, Cache<K, ListenableFuture<V>>> cacheBuilder,
        Function<ListenableSecurityCache<K, V, R>, StringKeyedInvalidatable> cacheInvalidatorBuilder,
        List<SecondaryCache<K, V, R>> secondaryCaches) {

        assert false == cacheInvalidationCallbacks.containsKey(name) : "Security cache of name [" + name + "] already exists";
        final ListenableSecurityCache<K, V, R> securityCache = new ListenableSecurityCache<>(name, cacheBuilder, secondaryCaches);
        cacheInvalidationCallbacks.put(name, cacheInvalidatorBuilder.apply(securityCache));
        return securityCache;
    }

    public static void onSecurityIndexStageChange(SecurityIndexManager.State previousState, SecurityIndexManager.State currentState) {
        if (isMoveFromRedToNonRed(previousState, currentState) || isIndexDeleted(previousState,
            currentState) || previousState.isIndexUpToDate != currentState.isIndexUpToDate) {
            cacheInvalidationCallbacks.values().forEach(StringKeyedInvalidatable::invalidateAll);
        }
    }

    // TODO: The static invalidation methods can be used to implement APIs for clearing named security caches:
    //       e.g. /_security/_cache/{name}/_clear_cache
    public static void invalidate(String name, Collection<String> keys) {
        final StringKeyedInvalidatable cacheInvalidator = cacheInvalidationCallbacks.get(name);
        if (cacheInvalidator != null) {
            cacheInvalidator.invalidate(keys);
        }
    }

    public static void invalidateAll(String name) {
        final StringKeyedInvalidatable cacheInvalidator = cacheInvalidationCallbacks.get(name);
        if (cacheInvalidator != null) {
            cacheInvalidator.invalidateAll();
        }
    }

    public interface Invalidatable<K> {
        void invalidate(Collection<K> keys);

        void invalidateAll();
    }

    public interface StringKeyedInvalidatable extends Invalidatable<String> {
        void invalidate(Collection<String> keys);

        void invalidateAll();

        static <K> StringKeyedInvalidatable withKeyConverter(Invalidatable<K> invalidatable, Function<String, K> keyConverter) {
            return new StringKeyedInvalidatable() {
                @Override
                public void invalidate(Collection<String> keys) {
                    invalidatable.invalidate(keys.stream().map(keyConverter).collect(Collectors.toUnmodifiableSet()));
                }

                @Override
                public void invalidateAll() {
                    invalidatable.invalidateAll();
                }
            };
        }

        static StringKeyedInvalidatable of(Invalidatable<String> invalidatable) {
            return StringKeyedInvalidatable.withKeyConverter(invalidatable, Function.identity());
        }
    }

    public interface SecondaryCache<K, V, T> {
        void cache(Tuple<K, V> primaryItem, T originalValue);

        void invalidate(Collection<Tuple<K, V>> primaryItems);

        void invalidateAll();
    }

    public static class DirectSecurityCache<K, V, R> implements Invalidatable<K> {

        private static final Logger logger = LogManager.getLogger(DirectSecurityCache.class);

        private final String name;
        private final Cache<K, V> delegate;
        private final List<SecondaryCache<K, V, R>> secondaryCaches;
        private final AtomicLong numInvalidation = new AtomicLong();
        private final ReadWriteLock invalidationLock = new ReentrantReadWriteLock();
        private final ReleasableLock invalidationReadLock = new ReleasableLock(invalidationLock.readLock());
        private final ReleasableLock invalidationWriteLock = new ReleasableLock(invalidationLock.writeLock());

        private DirectSecurityCache(
            String name,
            Function<RemovalListener<K, V>, Cache<K, V>> cacheBuilder,
            List<SecondaryCache<K, V, R>> secondaryCaches) {
            this.name = name;
            this.secondaryCaches = secondaryCaches;
            if (secondaryCaches.isEmpty()) {
                this.delegate = cacheBuilder.apply(null);
            } else {
                this.delegate = cacheBuilder.apply(notification -> {
                    try {
                        secondaryCaches.forEach(c -> c.invalidate(List.of(new Tuple<>(notification.getKey(), notification.getValue()))));
                    } catch (Exception e) {
                        logger.error("Cannot get value to invalidate", e);
                    }
                });
            }
        }

        // TODO: even if one is not found, fetch everything
        public Collection<V> get(Collection<K> keys, Consumer<ActionListener<Collection<R>>> getter, Function<R, V> transform) {
            return null;
        }

        // TODO: we may not wanna get value immediately if the given key is not found. think about grouping multiple fetches
        // TODO: We may not even wanna fetch with the key, e.g. application privilege cache
        public V get(K key, BiConsumer<K, ActionListener<R>> getter, Function<R, V> transform) {
            final V existing = delegate.get(key);
            final PlainActionFuture<R> future = PlainActionFuture.newFuture();
            if (existing == null) {
                final long invalidationCounter = numInvalidation.get();
                getter.accept(key, future);
                final R response;
                try {
                    response = future.get();
                } catch (InterruptedException | ExecutionException e) {
                    throw new RuntimeException(e);
                }
                final V value = transform.apply(response);
                try (ReleasableLock ignored = invalidationReadLock.acquire()) {
                    if (invalidationCounter == numInvalidation.get()) {
                        delegate.put(key, value);
                        secondaryCaches.forEach(c -> c.cache(new Tuple<>(key, value), response));
                    }
                }
                return value;
            } else {
                return existing;
            }
        }

        public V get(K key, BiConsumer<K, ActionListener<R>> getter) {
            return get(key, getter, r -> (V) r);
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

    public static class ListenableSecurityCache<K, V, R> implements Invalidatable<K> {

        private static final Logger logger = LogManager.getLogger(DirectSecurityCache.class);

        private final String name;
        private final Cache<K, ListenableFuture<V>> delegate;
        private final List<SecondaryCache<K, V, R>> secondaryCaches;
        private final AtomicLong numInvalidation = new AtomicLong();
        private final ReadWriteLock invalidationLock = new ReentrantReadWriteLock();
        private final ReleasableLock invalidationReadLock = new ReleasableLock(invalidationLock.readLock());
        private final ReleasableLock invalidationWriteLock = new ReleasableLock(invalidationLock.writeLock());

        private ListenableSecurityCache(
            String name,
            Function<RemovalListener<K, ListenableFuture<V>>, Cache<K, ListenableFuture<V>>> cacheBuilder,
            List<SecondaryCache<K, V, R>> secondaryCaches) {
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

        public ListenableFuture<V> get(K key, BiConsumer<K, ActionListener<R>> getter, Function<R, V> transform) throws ExecutionException {
            final AtomicBoolean valueAlreadyInCache = new AtomicBoolean(true);
            final ListenableFuture<V> listenableFuture = delegate.computeIfAbsent(key, k -> {
                valueAlreadyInCache.set(false);
                return new ListenableFuture<>();
            });
            // Value is not available yet, call getter for it
            if (false == valueAlreadyInCache.get()) {
                final long invalidationCounter = numInvalidation.get();
                getter.accept(key, new ActionListener<>() {
                    @Override
                    public void onResponse(R response) {
                        final V value = transform.apply(response);
                        listenableFuture.onResponse(value);
                        try (ReleasableLock ignored = invalidationReadLock.acquire()) {
                            if (invalidationCounter == numInvalidation.get()) {
                                logger.debug("Cache: [{}] - caching key [{}]", name, key);
                                secondaryCaches.forEach(c -> c.cache(new Tuple<>(key, value), response));
                            } else {
                                delegate.invalidate(key, listenableFuture);
                            }
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        delegate.invalidate(key, listenableFuture);
                        listenableFuture.cancel(false);
                    }
                });
            }
            return listenableFuture;
        }

        public ListenableFuture<V> get(K key, BiConsumer<K, ActionListener<R>> getter) throws ExecutionException {
            return get(key, getter, r -> (V) r);
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
}
