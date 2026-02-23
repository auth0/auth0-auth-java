package com.auth0.spring.boot;

import java.util.List;

/**
 * Functional interface for dynamically resolving allowed issuer domains
 * based on the incoming request context.
 * <p>
 * Used in Multi-Custom Domain (MCD) scenarios where the set of valid issuers
 * cannot be determined statically at configuration time. Define a Spring bean
 * implementing this interface, and the auto-configuration will pick it up
 * automatically.
 * </p>
 *
 * Example: Tenant-based resolution
 * 
 * <pre>{@code
 * @Bean
 * public Auth0DomainResolver domainResolver(TenantService tenantService) {
 *     return context -> {
 *         String tenantId = context.getHeaders().get("x-tenant-id");
 *         String domain = tenantService.getDomain(tenantId);
 *         return Collections.singletonList(domain);
 *     };
 * }
 * }</pre>
 *
 * Example: Issuer-hint based resolution
 * 
 * <pre>{@code
 * @Bean
 * public Auth0DomainResolver domainResolver() {
 *     return context -> {
 *         // Use the unverified iss claim as a routing hint
 *         String issuer = context.getTokenIssuer();
 *         if (issuer != null && allowedIssuers.contains(issuer)) {
 *             return Collections.singletonList(issuer);
 *         }
 *         return Collections.emptyList();
 *     };
 * }
 * }</pre>
 *
 * Priority
 * <p>
 * When an {@code Auth0DomainResolver} bean is present, it takes precedence
 * over the static {@code auth0.domains} YAML list. The single
 * {@code auth0.domain}
 * can still coexist as a fallback.
 * </p>
 *
 * @see Auth0RequestContext
 * @see Auth0Properties
 */
@FunctionalInterface
public interface Auth0DomainResolver {

    /**
     * Resolves the list of allowed issuer domains for the given request context.
     *
     * @param context the request context containing URL, headers, and
     *                unverified token issuer
     * @return a list of allowed issuer domain strings (e.g.,
     *         {@code ["login.acme.com", "auth.partner.com"]});
     *         may return {@code null} or an empty list if no domains can be
     *         resolved
     */
    List<String> resolveDomains(Auth0RequestContext context);
}
