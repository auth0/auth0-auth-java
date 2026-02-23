package com.auth0.cache;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe, in-memory LRU cache with TTL expiration.
 * <p>
 * This is the default {@link AuthCache} implementation shipped with the SDK.
 * It uses a {@link LinkedHashMap} in access-order mode for LRU eviction and
 * per-entry timestamps for TTL enforcement.
 * </p>
 *
 * <h3>Configuration</h3>
 * <ul>
 * <li><b>maxEntries</b> — maximum number of entries; LRU eviction when exceeded
 * (default: 100)</li>
 * <li><b>ttlSeconds</b> — time-to-live per entry in seconds (default: 600 = 10
 * minutes)</li>
 * </ul>
 *
 * <h3>Thread Safety</h3>
 * <p>
 * Uses a {@link ReentrantReadWriteLock} so concurrent reads do not block each
 * other,
 * while writes acquire exclusive access.
 * </p>
 *
 * @param <V> the type of cached values
 */
public class InMemoryAuthCache<V> implements AuthCache<V> {

    /** Default maximum number of entries. */
    public static final int DEFAULT_MAX_ENTRIES = 100;

    public static final long DEFAULT_TTL_SECONDS = 600;

    private final long ttlMillis;
    private final LinkedHashMap<String, CacheEntry<V>> store;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    /**
     * Creates a cache with default settings (100 entries, 10-minute TTL).
     */
    public InMemoryAuthCache() {
        this(DEFAULT_MAX_ENTRIES, DEFAULT_TTL_SECONDS);
    }

    /**
     * Creates a cache with the specified limits.
     *
     * @param maxEntries maximum number of entries before LRU eviction
     * @param ttlSeconds time-to-live per entry in seconds
     */
    public InMemoryAuthCache(int maxEntries, long ttlSeconds) {
        if (maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries must be positive");
        }
        if (ttlSeconds < 0) {
            throw new IllegalArgumentException("ttlSeconds must not be negative");
        }
        this.ttlMillis = ttlSeconds * 1000;
        // accessOrder=true makes LinkedHashMap maintain LRU order
        this.store = new LinkedHashMap<String, CacheEntry<V>>(maxEntries, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, CacheEntry<V>> eldest) {
                return size() > maxEntries;
            }
        };
    }

    @Override
    public V get(String key) {
        lock.writeLock().lock();
        try {
            CacheEntry<V> entry = store.get(key);
            if (entry == null) {
                return null;
            }
            if (isExpired(entry)) {
                store.remove(key);
                return null;
            }
            return entry.value;
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void put(String key, V value) {
        lock.writeLock().lock();
        try {
            store.put(key, new CacheEntry<>(value, System.currentTimeMillis()));
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void remove(String key) {
        lock.writeLock().lock();
        try {
            store.remove(key);
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void clear() {
        lock.writeLock().lock();
        try {
            store.clear();
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public int size() {
        lock.readLock().lock();
        try {
            return store.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    private boolean isExpired(CacheEntry<V> entry) {
        if (ttlMillis == 0) {
            return false; // TTL of 0 means no expiration
        }
        return (System.currentTimeMillis() - entry.createdAt) > ttlMillis;
    }

    /**
     * Internal wrapper that pairs a value with its insertion timestamp.
     */
    private static final class CacheEntry<V> {
        final V value;
        final long createdAt;

        CacheEntry(V value, long createdAt) {
            this.value = value;
            this.createdAt = createdAt;
        }
    }
}
