package com.auth0.spring.boot;

import com.auth0.AuthCache;
import com.auth0.AuthClient;
import com.auth0.DomainResolver;
import com.auth0.models.AuthOptions;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Autoconfiguration for Auth0 authentication and JWT validation.
 * <p>
 * Supports three domain configuration modes (mutually exclusive):
 * <ol>
 * <li><b>Single domain</b> — set {@code auth0.domain} in YAML</li>
 * <li><b>Static MCD list</b> — set {@code auth0.domains} in YAML</li>
 * <li><b>Dynamic resolver</b> — define a {@link DomainResolver} bean</li>
 * </ol>
 *
 * Dynamic Domain Resolver
 * <p>
 * To dynamically resolve allowed issuer domains at request time, define a bean
 * implementing {@link DomainResolver}:
 * </p>
 *
 * <pre>{@code
 * @Bean
 * public DomainResolver domainResolver() {
 *     return context -> {
 *         String tenantId = context.getHeaders().get("x-tenant-id");
 *         return lookupDomainsForTenant(tenantId);
 *     };
 * }
 * }</pre>
 */
@AutoConfiguration
@EnableConfigurationProperties(Auth0Properties.class)
public class Auth0AutoConfiguration {

    /**
     * Creates an {@link AuthOptions} bean from {@link Auth0Properties}.
     * <p>
     * Builds the authentication options configuration.
     *
     * @param properties             the Auth0 configuration properties from
     *                               application configuration
     * @param domainResolverProvider optional {@link DomainResolver} bean
     *                               for dynamic MCD resolution. When present,
     *                               it takes precedence over static YAML config.
     * @param cacheProvider          optional {@link AuthCache} bean for custom
     *                               caching (e.g., Redis). When present,
     *                               {@code cacheMaxEntries} and {@code cacheTtlSeconds}
     *                               properties are ignored.
     * @return configured AuthOptions instance for creating AuthClient
     * @see AuthOptions.Builder
     * @see Auth0Properties
     */
    @Bean
    public AuthOptions authOptions(Auth0Properties properties,
            ObjectProvider<DomainResolver> domainResolverProvider,
            ObjectProvider<AuthCache<Object>> cacheProvider) {

        DomainResolver domainResolver = domainResolverProvider.getIfAvailable();
        AuthCache<Object> cache = cacheProvider.getIfAvailable();

        AuthOptions.Builder builder = new AuthOptions.Builder()
                .audience(properties.getAudience());

        if (domainResolver != null) {
            builder.domainsResolver(domainResolver);

            if (properties.getDomain() != null && !properties.getDomain().isEmpty()) {
                builder.domain(properties.getDomain());
            }
        } else if (properties.getDomains() != null && !properties.getDomains().isEmpty()) {
            builder.domains(properties.getDomains());
            if (properties.getDomain() != null && !properties.getDomain().isEmpty()) {
                builder.domain(properties.getDomain());
            }
        } else {
            builder.domain(properties.getDomain());
        }

        if (properties.getDpopMode() != null) {
            builder.dpopMode(properties.getDpopMode());
        }

        if (properties.getDpopIatLeewaySeconds() != null) {
            builder.dpopIatLeewaySeconds(properties.getDpopIatLeewaySeconds());
        }
        if (properties.getDpopIatOffsetSeconds() != null) {
            builder.dpopIatOffsetSeconds(properties.getDpopIatOffsetSeconds());
        }

        if (cache != null) {
            builder.cache(cache);
        } else {
            if (properties.getCacheMaxEntries() != null) {
                builder.cacheMaxEntries(properties.getCacheMaxEntries());
            }
            if (properties.getCacheTtlSeconds() != null) {
                builder.cacheTtlSeconds(properties.getCacheTtlSeconds());
            }
        }

        return builder.build();
    }

    /**
     * Creates an {@link AuthClient} bean for request authentication and JWT validation.
     * <p>
     * Serves as the main entry point for verifying HTTP requests containing
     * access tokens.
     * @param options the AuthOptions configuration for creating the client
     * @return AuthClient instance configured with the specified options
     * @see AuthClient#from(AuthOptions)
     * @see AuthClient#verifyRequest(com.auth0.models.HttpRequestInfo)
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthClient authClient(AuthOptions options) {
        return AuthClient.from(options);
    }
}
