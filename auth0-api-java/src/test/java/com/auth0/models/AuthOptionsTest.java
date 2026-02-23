package com.auth0.models;

import com.auth0.DomainResolver;
import com.auth0.cache.AuthCache;
import com.auth0.cache.InMemoryAuthCache;
import com.auth0.enums.DPoPMode;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class AuthOptionsTest {

    @Test
    public void testBuilderSetsFieldsCorrectly() {
        AuthOptions options = new AuthOptions.Builder()
                .domain("example.com")
                .audience("api://default")
                .dpopMode(DPoPMode.REQUIRED)
                .dpopIatOffsetSeconds(600)
                .dpopIatLeewaySeconds(60)
                .build();

        assertEquals("example.com", options.getDomain());
        assertEquals("api://default", options.getAudience());
        assertEquals(DPoPMode.REQUIRED, options.getDpopMode());
        assertEquals(600, options.getDpopIatOffsetSeconds());
        assertEquals(60, options.getDpopIatLeewaySeconds());
        assertNull(options.getDomains());
        assertNull(options.getDomainsResolver());
    }

    @Test
    public void testBuilderWithDomainsStaticList() {
        List<String> domainList = Arrays.asList(
                "https://tenant1.auth0.com",
                "https://tenant2.auth0.com");

        AuthOptions options = new AuthOptions.Builder()
                .domains(domainList)
                .audience("api://default")
                .build();

        assertNull(options.getDomain());
        assertEquals(domainList, options.getDomains());
        assertNull(options.getDomainsResolver());
    }

    @Test
    public void testBuilderWithDomainsResolver() {
        DomainResolver resolver = context -> Collections.singletonList("https://resolved.auth0.com");

        AuthOptions options = new AuthOptions.Builder()
                .domainsResolver(resolver)
                .audience("api://default")
                .build();

        assertNull(options.getDomain());
        assertNull(options.getDomains());
        assertNotNull(options.getDomainsResolver());
    }

    @Test
    public void testBuilderWithDomainAndDomainsCoexist() {
        // Auth for Agents scenario: domain + domains can coexist
        List<String> domainList = Arrays.asList(
                "https://primary.auth0.com",
                "https://tenant2.auth0.com");

        AuthOptions options = new AuthOptions.Builder()
                .domain("primary.auth0.com")
                .domains(domainList)
                .audience("api://default")
                .build();

        assertEquals("primary.auth0.com", options.getDomain());
        assertEquals(domainList, options.getDomains());
    }

    @Test
    public void testBuilderThrowsWhenDomainsAndResolverBothSet() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new AuthOptions.Builder()
                        .domains(Collections.singletonList("https://tenant1.auth0.com"))
                        .domainsResolver(context -> Collections.singletonList("https://resolved.auth0.com"))
                        .audience("api://default")
                        .build());
        assertEquals("Cannot configure both 'domains' and 'domainsResolver'. Use one or the other.",
                exception.getMessage());
    }

    @Test
    public void testBuilderThrowsWhenNoDomainSourceProvided() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new AuthOptions.Builder()
                        .audience("api://default")
                        .build());
        assertEquals("At least one of 'domain', 'domains', or 'domainsResolver' must be configured.",
                exception.getMessage());
    }

    @Test
    public void testBuilderThrowsExceptionForNegativeIatOffset() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new AuthOptions.Builder().dpopIatOffsetSeconds(-1));
        assertEquals("dpopIatOffsetSeconds must not be negative", exception.getMessage());
    }

    @Test
    public void testBuilderThrowsExceptionForNegativeIatLeeway() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new AuthOptions.Builder().dpopIatLeewaySeconds(-1));
        assertEquals("dpopIatLeewaySeconds must not be negative", exception.getMessage());
    }

    @Test
    public void testBuildThrowsExceptionForNullAudience() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new AuthOptions.Builder()
                        .domain("example.com")
                        .build());
        assertEquals("Audience must not be null or empty", exception.getMessage());
    }

    @Test
    public void testDefaultValuesInBuilder() {
        AuthOptions options = new AuthOptions.Builder()
                .domain("example.com")
                .audience("api://default")
                .build();

        assertEquals(DPoPMode.ALLOWED, options.getDpopMode());
        assertEquals(300, options.getDpopIatOffsetSeconds());
        assertEquals(30, options.getDpopIatLeewaySeconds());
    }

    @Test
    public void testDomainsListIsUnmodifiable() {
        List<String> domainList = Arrays.asList("https://tenant1.auth0.com");

        AuthOptions options = new AuthOptions.Builder()
                .domains(domainList)
                .audience("api://default")
                .build();

        assertThrows(UnsupportedOperationException.class, () -> options.getDomains().add("https://evil.com"));
    }

    // -------------------------------------------------------------------
    // Cache configuration tests
    // -------------------------------------------------------------------

    @Test
    public void testDefaultCacheSettings() {
        AuthOptions options = new AuthOptions.Builder()
                .domain("example.com")
                .audience("api://default")
                .build();

        assertEquals(100, options.getCacheMaxEntries());
        assertEquals(600, options.getCacheTtlSeconds());
        assertNull(options.getCache());
    }

    @Test
    public void testCustomCacheMaxEntries() {
        AuthOptions options = new AuthOptions.Builder()
                .domain("example.com")
                .audience("api://default")
                .cacheMaxEntries(50)
                .build();

        assertEquals(50, options.getCacheMaxEntries());
    }

    @Test
    public void testCustomCacheTtlSeconds() {
        AuthOptions options = new AuthOptions.Builder()
                .domain("example.com")
                .audience("api://default")
                .cacheTtlSeconds(300)
                .build();

        assertEquals(300, options.getCacheTtlSeconds());
    }

    @Test
    public void testCacheTtlZeroMeansNoExpiration() {
        AuthOptions options = new AuthOptions.Builder()
                .domain("example.com")
                .audience("api://default")
                .cacheTtlSeconds(0)
                .build();

        assertEquals(0, options.getCacheTtlSeconds());
    }

    @Test
    public void testCustomCacheImplementation() {
        AuthCache<Object> customCache = new InMemoryAuthCache<>(200, 900);

        AuthOptions options = new AuthOptions.Builder()
                .domain("example.com")
                .audience("api://default")
                .cache(customCache)
                .build();

        assertSame(customCache, options.getCache());
    }

    @Test
    public void testBuilderThrowsForNonPositiveCacheMaxEntries() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new AuthOptions.Builder()
                        .domain("example.com")
                        .audience("api://default")
                        .cacheMaxEntries(0));
        assertEquals("cacheMaxEntries must be positive", exception.getMessage());
    }

    @Test
    public void testBuilderThrowsForNegativeCacheMaxEntries() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new AuthOptions.Builder()
                        .domain("example.com")
                        .audience("api://default")
                        .cacheMaxEntries(-5));
        assertEquals("cacheMaxEntries must be positive", exception.getMessage());
    }

    @Test
    public void testBuilderThrowsForNegativeCacheTtlSeconds() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new AuthOptions.Builder()
                        .domain("example.com")
                        .audience("api://default")
                        .cacheTtlSeconds(-1));
        assertEquals("cacheTtlSeconds must not be negative", exception.getMessage());
    }

    @Test
    public void testCacheSettingsWithAllCacheOptions() {
        AuthCache<Object> customCache = new InMemoryAuthCache<>(500, 1200);

        AuthOptions options = new AuthOptions.Builder()
                .domain("example.com")
                .audience("api://default")
                .cacheMaxEntries(250)
                .cacheTtlSeconds(900)
                .cache(customCache)
                .build();

        // When custom cache is set, it takes precedence
        assertSame(customCache, options.getCache());
        // The numeric settings are still stored (used as fallback if cache is null)
        assertEquals(250, options.getCacheMaxEntries());
        assertEquals(900, options.getCacheTtlSeconds());
    }
}