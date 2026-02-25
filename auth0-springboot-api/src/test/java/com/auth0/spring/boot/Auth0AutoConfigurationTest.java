package com.auth0.spring.boot;

import static org.junit.jupiter.api.Assertions.*;

import com.auth0.AuthClient;
import com.auth0.enums.DPoPMode;
import com.auth0.models.AuthOptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

/**
 * Test cases for Auth0AutoConfiguration
 *
 * <p>
 */
@SpringBootTest
@TestPropertySource(
    properties = {"auth0.domain=test-domain.auth0.com", "auth0.audience=https://api.example.com"})
class Auth0AutoConfigurationTest {

  @Autowired private ApplicationContext context;

  @Autowired private AuthOptions authOptions;

  @Autowired private AuthClient authClient;

  @Test
  @DisplayName("Should create AuthOptions bean with required domain and audience properties")
  void shouldCreateAuthOptionsBean() {
    assertNotNull(authOptions);
    assertEquals("test-domain.auth0.com", authOptions.getDomain());
    assertEquals("https://api.example.com", authOptions.getAudience());
  }

  @Test
  @DisplayName("Should create AuthClient bean configured with AuthOptions")
  void shouldCreateAuthClientBean() {
    assertNotNull(authClient);
    assertTrue(context.containsBean("authClient"));
  }

  @Test
  @DisplayName("Should register all auto-configuration beans in application context")
  void shouldRegisterAllBeansInContext() {
    assertTrue(context.containsBean("authOptions"));
    assertTrue(context.containsBean("authClient"));
  }

  @Nested
  @SpringBootTest
  @TestPropertySource(
      properties = {
        "auth0.domain=dpop-test.auth0.com",
        "auth0.audience=https://api.dpop.com",
        "auth0.dpop-mode=REQUIRED",
        "auth0.dpop-iat-leeway-seconds=10",
        "auth0.dpop-iat-offset-seconds=300"
      })
  class DPoPConfigurationTest {

    @Autowired private AuthOptions authOptions;

    @Test
    @DisplayName("Should configure AuthOptions with DPoP mode when dpop-mode property is set")
    void shouldConfigureDPoPMode() {
      assertNotNull(authOptions);
      assertEquals(DPoPMode.REQUIRED, authOptions.getDpopMode());
    }

    @Test
    @DisplayName("Should configure AuthOptions with DPoP IAT leeway seconds when property is set")
    void shouldConfigureDPoPIatLeewaySeconds() {
      assertNotNull(authOptions);
      assertEquals(10, authOptions.getDpopIatLeewaySeconds());
    }

    @Test
    @DisplayName("Should configure AuthOptions with DPoP IAT offset seconds when property is set")
    void shouldConfigureDPoPIatOffsetSeconds() {
      assertNotNull(authOptions);
      assertEquals(300, authOptions.getDpopIatOffsetSeconds());
    }
  }

  @Nested
  @SpringBootTest
  @TestPropertySource(
      properties = {
        "auth0.domain=minimal-test.auth0.com",
        "auth0.audience=https://api.minimal.com"
      })
  class MinimalConfigurationTest {

    @Autowired private AuthOptions authOptions;

    @Test
    @DisplayName(
        "Should configure AuthOptions with default DPoP settings when no DPoP properties are set")
    void shouldUseDefaultDPoPSettings() {
      assertNotNull(authOptions);
      assertEquals(DPoPMode.ALLOWED, authOptions.getDpopMode());
      assertEquals(30, authOptions.getDpopIatLeewaySeconds());
      assertEquals(300, authOptions.getDpopIatOffsetSeconds());
    }
  }

  @Nested
  @SpringBootTest
  @TestPropertySource(
      properties = {
        "auth0.domain=partial-dpop.auth0.com",
        "auth0.audience=https://api.partial.com",
        "auth0.dpop-mode=ALLOWED"
      })
  class PartialDPoPConfigurationTest {

    @Autowired private AuthOptions authOptions;

    @Test
    @DisplayName(
        "Should configure AuthOptions with only DPoP mode when other DPoP properties are not set")
    void shouldConfigureOnlyDPoPMode() {
      assertNotNull(authOptions);
      assertEquals(DPoPMode.ALLOWED, authOptions.getDpopMode());

      // Others should be set to their respective defaults
      assertEquals(30, authOptions.getDpopIatLeewaySeconds());
      assertEquals(300, authOptions.getDpopIatOffsetSeconds());
    }
  }
}
