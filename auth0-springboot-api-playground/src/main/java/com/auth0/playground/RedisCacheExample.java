package com.auth0.playground;

import com.auth0.AuthCache;

/**
 * Example: Using Redis as a distributed cache for OIDC discovery metadata and JWKS.
 * <p>
 * The SDK uses a unified cache with key prefixes:
 * <ul>
 * <li>{@code discovery:{issuerUrl}} — OIDC discovery metadata</li>
 * <li>{@code jwks:{jwksUri}} — JWKS provider instances</li>
 * </ul>
 * <p>
 * By implementing {@link AuthCache}, you can replace the default in-memory LRU
 * cache with any distributed backend (Redis, Memcached, etc.) without changing
 * any SDK internals.
 *
 * <h3>When to use a distributed cache</h3>
 * <ul>
 * <li>Multi-instance deployments where each node shouldn't fetch OIDC/JWKS independently</li>
 * <li>Reducing cold-start latency after deployments</li>
 * <li>Centralised cache invalidation across all API instances</li>
 * </ul>
 *
 * <h3>Spring Boot usage</h3>
 * <p>
 * Just define an {@link AuthCache} bean — the auto-configuration picks it up
 * automatically and wires it into {@code AuthOptions}. No need to create your
 * own {@code AuthClient} bean. When an {@code AuthCache} bean is present,
 * the {@code cacheMaxEntries} and {@code cacheTtlSeconds} YAML properties
 * are ignored.
 * </p>
 * <pre>{@code
 * @Configuration
 * public class CacheConfig {
 *     @Bean
 *     public AuthCache<Object> authCache(RedisTemplate<String, Object> redisTemplate) {
 *         return new RedisAuthCache(redisTemplate, 600);
 *     }
 * }
 * }</pre>
 *
 * <h3>Important notes</h3>
 * <ul>
 * <li>The cache stores mixed value types (OidcMetadata, JwkProvider) — the Redis
 *     serializer must handle this (e.g., Java serialization or a type-aware JSON strategy)</li>
 * <li>Implementations <b>must</b> be thread-safe</li>
 * <li>{@code get()} must return {@code null} for missing or expired keys — never throw</li>
 * </ul>
 */
public class RedisCacheExample {

    /**
     * Example Redis-backed implementation of {@link AuthCache}.
     * <p>
     * This is a reference implementation showing how to adapt a Redis client
     * to the SDK's cache interface. Replace the placeholder Redis operations
     * with your actual Redis client (Jedis, Lettuce, Spring RedisTemplate, etc.).
     */
    public static class RedisAuthCache implements AuthCache<Object> {

        // Replace with your actual Redis client
        // e.g., private final RedisTemplate<String, Object> redisTemplate;
        // e.g., private final JedisPool jedisPool;
        // e.g., private final RedisClient lettuceClient;

        private final long ttlSeconds;
        private final String keyPrefix;

        /**
         * Creates a Redis-backed auth cache.
         *
         * @param ttlSeconds time-to-live for cached entries in seconds
         */
        public RedisAuthCache(long ttlSeconds) {
            this(ttlSeconds, "auth0:");
        }

        /**
         * Creates a Redis-backed auth cache with a custom key prefix.
         *
         * @param ttlSeconds time-to-live for cached entries in seconds
         * @param keyPrefix  prefix for all Redis keys (e.g., "auth0:" to namespace)
         */
        public RedisAuthCache(long ttlSeconds, String keyPrefix) {
            this.ttlSeconds = ttlSeconds;
            this.keyPrefix = keyPrefix;
        }

        @Override
        public Object get(String key) {
            // Example with Spring RedisTemplate:
            //   return redisTemplate.opsForValue().get(keyPrefix + key);
            //
            // Example with Jedis:
            //   try (Jedis jedis = jedisPool.getResource()) {
            //       byte[] data = jedis.get((keyPrefix + key).getBytes());
            //       return data != null ? deserialize(data) : null;
            //   }
            //
            // Must return null for missing/expired keys — never throw
            return null;
        }

        @Override
        public void put(String key, Object value) {
            // Example with Spring RedisTemplate:
            //   redisTemplate.opsForValue().set(keyPrefix + key, value, Duration.ofSeconds(ttlSeconds));
            //
            // Example with Jedis:
            //   try (Jedis jedis = jedisPool.getResource()) {
            //       jedis.setex((keyPrefix + key).getBytes(), ttlSeconds, serialize(value));
            //   }
            //
            // The SDK stores both OIDC metadata and JWKS providers using
            // prefixed keys like "discovery:https://tenant.auth0.com/"
            // and "jwks:https://tenant.auth0.com/.well-known/jwks.json"
        }

        @Override
        public void remove(String key) {
            // Example with Spring RedisTemplate:
            //   redisTemplate.delete(keyPrefix + key);
            //
            // Example with Jedis:
            //   try (Jedis jedis = jedisPool.getResource()) {
            //       jedis.del((keyPrefix + key).getBytes());
            //   }
        }

        @Override
        public void clear() {
            // Example with Spring RedisTemplate (scan + delete):
            //   Set<String> keys = redisTemplate.keys(keyPrefix + "*");
            //   if (keys != null && !keys.isEmpty()) {
            //       redisTemplate.delete(keys);
            //   }
            //
            // WARNING: KEYS command is expensive in production.
            // Consider using SCAN or maintaining a key set for bulk deletion.
        }

        @Override
        public int size() {
            // Example with Spring RedisTemplate:
            //   Set<String> keys = redisTemplate.keys(keyPrefix + "*");
            //   return keys != null ? keys.size() : 0;
            //
            // This is an approximation — exact count may vary due to TTL expiry.
            return 0;
        }
    }

}
