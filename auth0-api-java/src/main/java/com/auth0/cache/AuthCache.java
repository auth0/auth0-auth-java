package com.auth0.cache;

/**
 * Cache abstraction for storing authentication-related data such as
 * OIDC discovery metadata and JWKS providers.
 * <p>
 * The SDK ships with a default in-memory LRU implementation
 * ({@link InMemoryAuthCache}). Developers can implement this interface
 * to plug in distributed cache backends (e.g., Redis, Memcached) without
 * breaking changes to the SDK's public API.
 * </p>
 *
 * <h3>Unified cache with key prefixes</h3>
 * <p>
 * A single {@code AuthCache<Object>} instance can serve as a unified cache
 * for both discovery metadata and JWKS providers by using key prefixes:
 * </p>
 * <ul>
 * <li>{@code discovery:{issuerUrl}} — OIDC discovery metadata</li>
 * <li>{@code jwks:{jwksUri}} — JwkProvider instances</li>
 * </ul>
 *
 * <h3>Thread Safety</h3>
 * <p>
 * All implementations <b>must</b> be thread-safe.
 * </p>
 *
 * @param <V> the type of cached values
 */
public interface AuthCache<V> {

    /**
     * Retrieves a value from the cache.
     *
     * @param key the cache key
     * @return the cached value, or {@code null} if not present or expired
     */
    V get(String key);

    /**
     * Stores a value in the cache with the cache's default TTL.
     *
     * @param key   the cache key
     * @param value the value to cache
     */
    void put(String key, V value);

    /**
     * Removes a specific entry from the cache.
     *
     * @param key the cache key to remove
     */
    void remove(String key);

    /**
     * Removes all entries from the cache.
     */
    void clear();

    /**
     * Returns the number of entries currently in the cache.
     *
     * @return the cache size
     */
    int size();
}
