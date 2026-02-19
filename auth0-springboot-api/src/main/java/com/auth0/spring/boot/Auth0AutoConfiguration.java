package com.auth0.spring.boot;

import com.auth0.AuthClient;
import com.auth0.models.AuthOptions;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Autoconfiguration for Auth0 authentication and JWT validation.
 */
@AutoConfiguration
@EnableConfigurationProperties(Auth0Properties.class)
public class Auth0AutoConfiguration {
    /**
     * Creates an {@link AuthOptions} bean from {@link Auth0Properties}.
     * <p>
     * Builds the authentication options configuration.
     * @param properties the Auth0 configuration properties from application configuration
     * @return configured AuthOptions instance for creating AuthClient
     * @see AuthOptions.Builder
     * @see Auth0Properties
     */
    @Bean
    public AuthOptions authOptions(Auth0Properties properties) {

        AuthOptions.Builder builder = new AuthOptions.Builder()
                .domain(properties.getDomain())
                .audience(properties.getAudience());

        if (properties.getDpopMode() != null) {
            builder.dpopMode(properties.getDpopMode());
        }

        if (properties.getDpopIatLeewaySeconds() != null) {
            builder.dpopIatLeewaySeconds(properties.getDpopIatLeewaySeconds());
        }
        if (properties.getDpopIatOffsetSeconds() != null) {
            builder.dpopIatOffsetSeconds(properties.getDpopIatOffsetSeconds());
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
