package com.auth0.spring.boot;

import com.auth0.enums.DPoPMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test cases for Auth0Properties
 */
class Auth0PropertiesTest {

    private Auth0Properties properties;

    @BeforeEach
    void setUp() {
        properties = new Auth0Properties();
    }

    @Test
    @DisplayName("Should set and get domain property")
    void shouldSetAndGetDomain() {
        String domain = "dev-tenant.us.auth0.com";
        properties.setDomain(domain);

        assertEquals(domain, properties.getDomain());
    }

    @Test
    @DisplayName("Should set and get audience property")
    void shouldSetAndGetAudience() {
        String audience = "https://api.example.com/v2/";
        properties.setAudience(audience);

        assertEquals(audience, properties.getAudience());
    }

    @Test
    @DisplayName("Should set and get dpopMode property")
    void shouldSetAndGetDpopMode() {
        properties.setDpopMode(DPoPMode.REQUIRED);
        assertEquals(DPoPMode.REQUIRED, properties.getDpopMode());

        properties.setDpopMode(DPoPMode.ALLOWED);
        assertEquals(DPoPMode.ALLOWED, properties.getDpopMode());

        properties.setDpopMode(DPoPMode.DISABLED);
        assertEquals(DPoPMode.DISABLED, properties.getDpopMode());
    }

    @Test
    @DisplayName("Should set and get dpopIatOffsetSeconds property")
    void shouldSetAndGetDpopIatOffsetSeconds() {
        Long offsetSeconds = 300L;
        properties.setDpopIatOffsetSeconds(offsetSeconds);

        assertEquals(offsetSeconds, properties.getDpopIatOffsetSeconds());
    }

    @Test
    @DisplayName("Should set and get dpopIatLeewaySeconds property")
    void shouldSetAndGetDpopIatLeewaySeconds() {
        Long leewaySeconds = 60L;
        properties.setDpopIatLeewaySeconds(leewaySeconds);

        assertEquals(leewaySeconds, properties.getDpopIatLeewaySeconds());
    }

    @Test
    @DisplayName("Should have null default values for all properties")
    void shouldHaveNullDefaultValues() {
        assertNull(properties.getDomain());
        assertNull(properties.getAudience());
        assertNull(properties.getDpopMode());
        assertNull(properties.getDpopIatOffsetSeconds());
        assertNull(properties.getDpopIatLeewaySeconds());
    }

    @Test
    @DisplayName("Should handle null values for all properties")
    void shouldHandleNullValues() {
        properties.setDomain("test.com");
        properties.setDomain(null);
        assertNull(properties.getDomain());

        properties.setAudience("https://api.test.com");
        properties.setAudience(null);
        assertNull(properties.getAudience());

        properties.setDpopMode(DPoPMode.REQUIRED);
        properties.setDpopMode(null);
        assertNull(properties.getDpopMode());

        properties.setDpopIatOffsetSeconds(100L);
        properties.setDpopIatOffsetSeconds(null);
        assertNull(properties.getDpopIatOffsetSeconds());

        properties.setDpopIatLeewaySeconds(50L);
        properties.setDpopIatLeewaySeconds(null);
        assertNull(properties.getDpopIatLeewaySeconds());
    }

    @Test
    @DisplayName("Should allow zero values for DPoP timing properties")
    void shouldAllowZeroValuesForDpopTimingProperties() {
        properties.setDpopIatOffsetSeconds(0L);
        assertEquals(0L, properties.getDpopIatOffsetSeconds());

        properties.setDpopIatLeewaySeconds(0L);
        assertEquals(0L, properties.getDpopIatLeewaySeconds());
    }

    @Test
    @DisplayName("Should reject negative values for DPoP timing properties")
    void shouldRejectNegativeValuesForDpopTimingProperties() {
        assertThrows(IllegalArgumentException.class, () -> properties.setDpopIatOffsetSeconds(-100L));

        assertThrows(IllegalArgumentException.class, () -> properties.setDpopIatLeewaySeconds(-50L));
    }

    // ── Multi-Custom Domain (MCD) Tests ──────────────────────────────────

    @Test
    @DisplayName("Should set and get domains list for MCD support")
    void shouldSetAndGetDomains() {
        List<String> domains = Arrays.asList("login.acme.com", "auth.partner.com");
        properties.setDomains(domains);

        assertEquals(domains, properties.getDomains());
        assertEquals(2, properties.getDomains().size());
        assertEquals("login.acme.com", properties.getDomains().get(0));
        assertEquals("auth.partner.com", properties.getDomains().get(1));
    }

    @Test
    @DisplayName("Should have null default value for domains")
    void shouldHaveNullDefaultForDomains() {
        assertNull(properties.getDomains());
    }

    @Test
    @DisplayName("Should handle empty domains list")
    void shouldHandleEmptyDomainsList() {
        properties.setDomains(Collections.emptyList());
        assertNotNull(properties.getDomains());
        assertTrue(properties.getDomains().isEmpty());
    }

    @Test
    @DisplayName("Should handle single domain in domains list")
    void shouldHandleSingleDomainInList() {
        properties.setDomains(Collections.singletonList("login.acme.com"));
        assertEquals(1, properties.getDomains().size());
        assertEquals("login.acme.com", properties.getDomains().get(0));
    }

    @Test
    @DisplayName("Should allow domains and domain to coexist")
    void shouldAllowDomainsAndDomainToCoexist() {
        properties.setDomain("primary.auth0.com");
        properties.setDomains(Arrays.asList("login.acme.com", "auth.partner.com"));

        assertEquals("primary.auth0.com", properties.getDomain());
        assertEquals(2, properties.getDomains().size());
    }

    @Test
    @DisplayName("Should handle null domains value")
    void shouldHandleNullDomainsValue() {
        properties.setDomains(Arrays.asList("login.acme.com"));
        properties.setDomains(null);
        assertNull(properties.getDomains());
    }
}