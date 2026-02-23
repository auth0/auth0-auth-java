package com.auth0.cache;

import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class InMemoryAuthCacheTest {

    private InMemoryAuthCache<String> cache;

    @Before
    public void setUp() {
        cache = new InMemoryAuthCache<>();
    }

    @Test
    public void defaultConstructor_shouldUseDefaultSettings() {
        InMemoryAuthCache<Object> c = new InMemoryAuthCache<>();
        assertThat(c.size()).isZero();
    }

    @Test
    public void constructor_shouldRejectZeroMaxEntries() {
        assertThatThrownBy(() -> new InMemoryAuthCache<>(0, 600))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("maxEntries must be positive");
    }

    @Test
    public void constructor_shouldRejectNegativeMaxEntries() {
        assertThatThrownBy(() -> new InMemoryAuthCache<>(-1, 600))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("maxEntries must be positive");
    }

    @Test
    public void constructor_shouldRejectNegativeTtl() {
        assertThatThrownBy(() -> new InMemoryAuthCache<>(10, -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("ttlSeconds must not be negative");
    }

    @Test
    public void constructor_shouldAcceptZeroTtlMeaningNoExpiration() {
        InMemoryAuthCache<String> c = new InMemoryAuthCache<>(10, 0);
        c.put("key", "value");
        assertThat(c.get("key")).isEqualTo("value");
    }

    @Test
    public void put_andGet_shouldStoreAndRetrieveValue() {
        cache.put("key1", "value1");
        assertThat(cache.get("key1")).isEqualTo("value1");
    }

    @Test
    public void get_shouldReturnNullForMissingKey() {
        assertThat(cache.get("nonexistent")).isNull();
    }

    @Test
    public void put_shouldOverwriteExistingValue() {
        cache.put("key1", "first");
        cache.put("key1", "second");
        assertThat(cache.get("key1")).isEqualTo("second");
        assertThat(cache.size()).isEqualTo(1);
    }

    @Test
    public void remove_shouldDeleteEntry() {
        cache.put("key1", "value1");
        cache.remove("key1");
        assertThat(cache.get("key1")).isNull();
        assertThat(cache.size()).isZero();
    }

    @Test
    public void remove_shouldBeNoOpForMissingKey() {
        cache.remove("nonexistent"); // should not throw
        assertThat(cache.size()).isZero();
    }

    @Test
    public void clear_shouldRemoveAllEntries() {
        cache.put("a", "1");
        cache.put("b", "2");
        cache.put("c", "3");
        assertThat(cache.size()).isEqualTo(3);

        cache.clear();
        assertThat(cache.size()).isZero();
        assertThat(cache.get("a")).isNull();
    }

    @Test
    public void size_shouldReturnNumberOfEntries() {
        assertThat(cache.size()).isZero();
        cache.put("a", "1");
        assertThat(cache.size()).isEqualTo(1);
        cache.put("b", "2");
        assertThat(cache.size()).isEqualTo(2);
    }

    @Test
    public void lruEviction_shouldRemoveEldestEntryWhenMaxEntriesExceeded() {
        InMemoryAuthCache<String> lruCache = new InMemoryAuthCache<>(3, 600);

        lruCache.put("a", "1");
        lruCache.put("b", "2");
        lruCache.put("c", "3");
        // Cache is full. Adding a 4th entry should evict "a" (least recently used).
        lruCache.put("d", "4");

        assertThat(lruCache.size()).isEqualTo(3);
        assertThat(lruCache.get("a")).isNull(); // evicted
        assertThat(lruCache.get("b")).isEqualTo("2");
        assertThat(lruCache.get("c")).isEqualTo("3");
        assertThat(lruCache.get("d")).isEqualTo("4");
    }

    @Test
    public void lruEviction_accessShouldRefreshOrder() {
        InMemoryAuthCache<String> lruCache = new InMemoryAuthCache<>(3, 600);

        lruCache.put("a", "1");
        lruCache.put("b", "2");
        lruCache.put("c", "3");

        lruCache.get("a");

        lruCache.put("d", "4");

        assertThat(lruCache.get("b")).isNull();
        assertThat(lruCache.get("a")).isEqualTo("1");
        assertThat(lruCache.get("c")).isEqualTo("3");
        assertThat(lruCache.get("d")).isEqualTo("4");
    }

    @Test
    public void ttlExpiration_shouldEvictExpiredEntries() throws InterruptedException {
        InMemoryAuthCache<String> ttlCache = new InMemoryAuthCache<>(100, 1);

        ttlCache.put("key", "value");
        assertThat(ttlCache.get("key")).isEqualTo("value");

        // Wait for TTL to expire
        Thread.sleep(1200);

        assertThat(ttlCache.get("key")).isNull();
    }

    @Test
    public void zeroTtl_shouldNeverExpire() throws InterruptedException {
        InMemoryAuthCache<String> noExpireCache = new InMemoryAuthCache<>(100, 0);

        noExpireCache.put("key", "value");
        // Even after a short sleep, entries should remain
        Thread.sleep(50);
        assertThat(noExpireCache.get("key")).isEqualTo("value");
    }

    @Test
    public void unifiedCache_shouldSupportDifferentPrefixes() {
        InMemoryAuthCache<Object> unified = new InMemoryAuthCache<>();

        unified.put("discovery:https://tenant.auth0.com/", "metadata-object");
        unified.put("jwks:https://tenant.auth0.com/.well-known/jwks.json", "jwk-provider-object");

        assertThat(unified.get("discovery:https://tenant.auth0.com/")).isEqualTo("metadata-object");
        assertThat(unified.get("jwks:https://tenant.auth0.com/.well-known/jwks.json")).isEqualTo("jwk-provider-object");
        assertThat(unified.size()).isEqualTo(2);
    }

    @Test
    public void concurrentAccess_shouldNotCorruptState() throws InterruptedException {
        InMemoryAuthCache<Integer> concurrentCache = new InMemoryAuthCache<>(1000, 600);
        int threadCount = 10;
        int opsPerThread = 100;
        Thread[] threads = new Thread[threadCount];

        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            threads[t] = new Thread(() -> {
                for (int i = 0; i < opsPerThread; i++) {
                    String key = "t" + threadId + "-k" + i;
                    concurrentCache.put(key, i);
                    concurrentCache.get(key);
                }
            });
        }

        for (Thread thread : threads) {
            thread.start();
        }
        for (Thread thread : threads) {
            thread.join();
        }

        assertThat(concurrentCache.size()).isLessThanOrEqualTo(1000);
        assertThat(concurrentCache.size()).isGreaterThan(0);
    }
}
