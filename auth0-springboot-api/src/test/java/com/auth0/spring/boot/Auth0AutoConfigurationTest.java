package com.auth0.spring.boot;

import com.auth0.AuthClient;
import com.auth0.DomainResolver;
import com.auth0.models.AuthOptions;
import com.auth0.enums.DPoPMode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Test cases for Auth0AutoConfiguration
 * <p>
 */
@SpringBootTest
@TestPropertySource(properties = {
        "auth0.domain=test-domain.auth0.com",
        "auth0.audience=https://api.example.com"
})
class Auth0AutoConfigurationTest {

    @Autowired
    private ApplicationContext context;

    @Autowired
    private AuthOptions authOptions;

    @Autowired
    private AuthClient authClient;

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
    @TestPropertySource(properties = {
            "auth0.domain=dpop-test.auth0.com",
            "auth0.audience=https://api.dpop.com",
            "auth0.dpop-mode=REQUIRED",
            "auth0.dpop-iat-leeway-seconds=10",
            "auth0.dpop-iat-offset-seconds=300"
    })
    class DPoPConfigurationTest {

        @Autowired
        private AuthOptions authOptions;

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
    @TestPropertySource(properties = {
            "auth0.domain=minimal-test.auth0.com",
            "auth0.audience=https://api.minimal.com"
    })
    class MinimalConfigurationTest {

        @Autowired
        private AuthOptions authOptions;

        @Test
        @DisplayName("Should configure AuthOptions with default DPoP settings when no DPoP properties are set")
        void shouldUseDefaultDPoPSettings() {
            assertNotNull(authOptions);
            assertEquals(DPoPMode.ALLOWED, authOptions.getDpopMode());
            assertEquals(30, authOptions.getDpopIatLeewaySeconds());
            assertEquals(300, authOptions.getDpopIatOffsetSeconds());
        }
    }

    @Nested
    @SpringBootTest
    @TestPropertySource(properties = {
            "auth0.domain=partial-dpop.auth0.com",
            "auth0.audience=https://api.partial.com",
            "auth0.dpop-mode=ALLOWED"
    })
    class PartialDPoPConfigurationTest {

        @Autowired
        private AuthOptions authOptions;

        @Test
        @DisplayName("Should configure AuthOptions with only DPoP mode when other DPoP properties are not set")
        void shouldConfigureOnlyDPoPMode() {
            assertNotNull(authOptions);
            assertEquals(DPoPMode.ALLOWED, authOptions.getDpopMode());

            // Others should be set to their respective defaults
            assertEquals(30, authOptions.getDpopIatLeewaySeconds());
            assertEquals(300, authOptions.getDpopIatOffsetSeconds());
        }
    }

    @Nested
    @SpringBootTest
    @TestPropertySource(properties = {
            "auth0.domain=",
            "auth0.audience=https://api.mcd.com",
            "auth0.domains[0]=login.acme.com",
            "auth0.domains[1]=auth.partner.com",
            "auth0.domains[2]=dev.example.com"
    })
    class McdDomainsConfigurationTest {

        @Autowired
        private AuthOptions authOptions;

        @Test
        @DisplayName("Should configure AuthOptions with domains list from YAML")
        void shouldConfigureDomainsFromYaml() {
            assertNotNull(authOptions);
            List<String> domains = authOptions.getDomains();
            assertNotNull(domains);
            assertEquals(3, domains.size());
            assertEquals("login.acme.com", domains.get(0));
            assertEquals("auth.partner.com", domains.get(1));
            assertEquals("dev.example.com", domains.get(2));
        }

        @Test
        @DisplayName("Should not set single domain when only domains list is configured")
        void shouldNotSetSingleDomainWhenOnlyDomainsConfigured() {
            assertNull(authOptions.getDomain());
        }
    }

    @Nested
    @SpringBootTest
    @TestPropertySource(properties = {
            "auth0.domain=primary.auth0.com",
            "auth0.audience=https://api.mcd.com",
            "auth0.domains[0]=login.acme.com",
            "auth0.domains[1]=auth.partner.com"
    })
    class McdDomainsWithPrimaryDomainTest {

        @Autowired
        private AuthOptions authOptions;

        @Test
        @DisplayName("Should configure both domain and domains when both are set")
        void shouldConfigureBothDomainAndDomains() {
            assertNotNull(authOptions);
            // Primary domain is also set for Auth for Agents scenarios
            assertEquals("primary.auth0.com", authOptions.getDomain());

            List<String> domains = authOptions.getDomains();
            assertNotNull(domains);
            assertEquals(2, domains.size());
            assertEquals("login.acme.com", domains.get(0));
            assertEquals("auth.partner.com", domains.get(1));
        }
    }

    @Nested
    @SpringBootTest
    @TestPropertySource(properties = {
            "auth0.domain=single.auth0.com",
            "auth0.audience=https://api.single.com"
    })
    class SingleDomainFallbackTest {

        @Autowired
        private AuthOptions authOptions;

        @Test
        @DisplayName("Should fall back to single domain when domains list is not configured")
        void shouldFallBackToSingleDomain() {
            assertNotNull(authOptions);
            assertEquals("single.auth0.com", authOptions.getDomain());
            assertNull(authOptions.getDomains());
        }
    }

    @Nested
    @SpringBootTest(classes = {
            Auth0AutoConfiguration.class,
            DomainResolverBeanTest.TestConfig.class
    })
    @TestPropertySource(properties = {
            "auth0.domain=fallback.auth0.com",
            "auth0.audience=https://api.resolver.com"
    })
    class DomainResolverBeanTest {

        @TestConfiguration
        static class TestConfig {
            @Bean
            public DomainResolver testDomainResolver() {
                return context -> {
                    String tenant = context.getHeaders().get("x-tenant-id");
                    if ("acme".equals(tenant)) {
                        return Collections.singletonList("login.acme.com");
                    }
                    return Arrays.asList("default1.auth0.com", "default2.auth0.com");
                };
            }
        }

        @Autowired
        private AuthOptions authOptions;

        @Test
        @DisplayName("Should use DomainResolver bean when present, taking priority over domains list")
        void shouldUseResolverBeanWhenPresent() {
            assertNotNull(authOptions);
            // When a resolver is present, domainsResolver should be set
            assertNotNull(authOptions.getDomainsResolver());
            // Static domains list should NOT be set (resolver takes priority)
            assertNull(authOptions.getDomains());
        }

        @Test
        @DisplayName("Should preserve single domain as fallback alongside resolver")
        void shouldPreserveSingleDomainWithResolver() {
            assertEquals("fallback.auth0.com", authOptions.getDomain());
        }
    }

    @Nested
    @SpringBootTest(classes = {
            Auth0AutoConfiguration.class,
            ResolverPriorityOverDomainsTest.TestConfig.class
    })
    @TestPropertySource(properties = {
            "auth0.domain=primary.auth0.com",
            "auth0.audience=https://api.priority.com",
            "auth0.domains[0]=static1.auth0.com",
            "auth0.domains[1]=static2.auth0.com"
    })
    class ResolverPriorityOverDomainsTest {

        @TestConfiguration
        static class TestConfig {
            @Bean
            public DomainResolver testDomainResolver() {
                return context -> Collections.singletonList("dynamic.auth0.com");
            }
        }

        @Autowired
        private AuthOptions authOptions;

        @Test
        @DisplayName("Should prioritize DomainResolver over static domains list")
        void shouldPrioritizeResolverOverStaticDomains() {
            assertNotNull(authOptions);
            // Resolver should win over static domains
            assertNotNull(authOptions.getDomainsResolver());
            // Static domains should NOT be set since resolver takes priority
            assertNull(authOptions.getDomains());
        }
    }
}