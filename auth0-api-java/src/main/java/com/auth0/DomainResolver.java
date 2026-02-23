package com.auth0;

import com.auth0.models.RequestContext;

import java.util.List;

/**
 * Functional interface for dynamically resolving allowed issuer domains
 * based on the incoming request context.
 * <p>
 * Used in multi-custom-domain (MCD) scenarios where the set of valid issuers
 * cannot be determined statically at configuration time. The resolver receives
 * a {@link RequestContext} containing the request URL, headers, and the
 * unverified token issuer, and returns the list of allowed issuer domains.
 * </p>
 *
 * <pre>{@code
 * AuthOptions options = new AuthOptions.Builder()
 *         .domainsResolver(context -> {
 *             String host = context.getHeaders().get("host");
 *             return lookupIssuersForHost(host);
 *         })
 *         .audience("https://api.example.com")
 *         .build();
 * }</pre>
 *
 * @see RequestContext
 * @see com.auth0.models.AuthOptions.Builder#domainsResolver(DomainResolver)
 */
@FunctionalInterface
public interface DomainResolver {

    /**
     * Resolves the list of allowed issuer domains for the given request context.
     *
     * @param context the request context containing URL, headers, and unverified
     *                token issuer
     * @return a list of allowed issuer domain strings (e.g.,
     *         {@code ["https://tenant1.auth0.com/"]});
     *         may return {@code null} or an empty list if no domains can be
     *         resolved
     */
    List<String> resolveDomains(RequestContext context);
}
