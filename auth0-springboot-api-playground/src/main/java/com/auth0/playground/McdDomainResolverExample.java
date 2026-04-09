package com.auth0.playground;

import com.auth0.DomainResolver;
import com.auth0.models.RequestContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Example: Multi-Custom Domain (MCD) configuration with a dynamic domain
 * resolver.
 * <p>
 * Demonstrates how an end developer uses {@link DomainResolver} to dynamically
 * resolve allowed issuer domains at request time.
 * </p>
 *
 * <h3>How it works</h3>
 * <ol>
 * <li>Define a {@link DomainResolver} bean in a {@code @Configuration}
 * class</li>
 * <li>The auto-configuration picks it up and passes it to the SDK's
 * domain resolution pipeline</li>
 * <li>On each request, the resolver receives a {@link RequestContext}
 * containing the request URL, headers, and unverified token issuer</li>
 * <li>The resolver returns the list of allowed issuer domains for that
 * request</li>
 * </ol>
 *
 * <h3>Activation</h3>
 * <p>
 * Just define this {@code @Configuration} class in your project.
 * The auto-configuration detects the {@link DomainResolver} bean
 * automatically — no extra YAML properties needed.
 * </p>
 *
 * <h3>Real-world scenarios</h3>
 * <ul>
 * <li><b>Tenant routing</b> — resolve domains from a tenant header or
 * database</li>
 * <li><b>Host-based routing</b> — map the incoming Host header to an Auth0
 * domain</li>
 * <li><b>Issuer-hint routing</b> — validate the unverified {@code iss} claim
 * against a known allowlist</li>
 * </ul>
 *
 * @see DomainResolver
 * @see RequestContext
 */
@Configuration
public class McdDomainResolverExample {

    /**
     * Simulated tenant → Auth0 domain mapping.
     * <p>
     * In a real application, this would come from a database, external service,
     * or configuration store.
     * </p>
     */
    private static final Map<String, List<String>> TENANT_DOMAINS = Map.of(
            "tanya", Collections.singletonList("login.acme.com"),
            "partner", Collections.singletonList("auth.partner.com"),
            "default", Arrays.asList("abcd.org", "pqr.com"));

    /**
     * Dynamic domain resolver that resolves allowed issuers based on the
     * {@code X-Tenant-ID} request header.
     * <p>
     * The resolver receives a {@link RequestContext} with:
     * <ul>
     * <li>{@code context.getUrl()} — the API request URL</li>
     * <li>{@code context.getHeaders()} — all request headers (lowercase keys)</li>
     * <li>{@code context.getTokenIssuer()} — the <b>unverified</b> {@code iss}
     * claim from the JWT (use as a routing hint only)</li>
     * </ul>
     *
     * <h4>Example request</h4>
     *
     * <pre>
     * curl -H "Authorization: Bearer eyJ..." \
     *      -H "X-Tenant-ID: acme" \
     *      http://localhost:8080/api/protected
     * </pre>
     *
     * @return a {@link DomainResolver} that maps tenant IDs to Auth0 domains
     */
    @Bean
    public DomainResolver domainResolver() {
        return context -> {
            String tenantId = context.getHeaders().get("x-tenant-id");

            if (tenantId != null && TENANT_DOMAINS.containsKey(tenantId)) {
                List<String> domains = TENANT_DOMAINS.get(tenantId);
                return domains;
            }

            List<String> defaults = TENANT_DOMAINS.get("default");
            return defaults;
        };
    }
}
