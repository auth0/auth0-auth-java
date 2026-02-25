package com.auth0.spring.boot;

import static org.junit.jupiter.api.Assertions.*;

import com.auth0.enums.DPoPMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Test cases for Auth0Properties */
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
}
