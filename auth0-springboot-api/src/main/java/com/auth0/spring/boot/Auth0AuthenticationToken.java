package com.auth0.spring.boot;

import com.auth0.models.AuthenticationContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Spring Security Authentication object representing a successfully validated Auth0 JWT.
 * <p>
 * Authorities are derived from the "scope" claim in the JWT, if present, and mapped
 * to {@code SCOPE_} prefixed {@link SimpleGrantedAuthority} instances. If no scopes
 * are present, a default {@code ROLE_USER} authority is assigned.
 */
public class Auth0AuthenticationToken extends AbstractAuthenticationToken {
    private final AuthenticationContext authenticationContext;
    private final String principal;

    /**
     * Constructs a new {@code Auth0AuthenticationToken} from the given {@link AuthenticationContext}.
     * <p>
     * Extracts authorities from the "scope" claim and sets the principal to the "sub" claim.
     *
     * @param authenticationContext the validated Auth0 authentication context
     */
    public Auth0AuthenticationToken(AuthenticationContext authenticationContext) {
        super(createAuthorities(authenticationContext));
        this.authenticationContext = authenticationContext;
        this.principal = (String) authenticationContext.getClaims().get("sub");
        setAuthenticated(true);
    }

     static Collection<? extends GrantedAuthority> createAuthorities(AuthenticationContext ctx) {
        Object scopeClaim = ctx.getClaims().get("scope");

        if (scopeClaim instanceof String && !((String) scopeClaim).isBlank()) {
            String scopes = (String) scopeClaim;
            List<String> authorities = List.of(scopes.trim().split("\\s+"));

            return authorities.stream()
                    .map(scope -> "SCOPE_" + scope)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }

        return AuthorityUtils.createAuthorityList("ROLE_USER");
    }

    /**
     * Returns the credentials for this authentication token.
     * <p>
     * Always returns {@code null} as credentials are not exposed.
     *
     * @return {@code null}
     */
    @Override
    public Object getCredentials() {
        return null;
    }

    /**
     * Returns the principal identifier for this authentication token.
     * <p>
     * Typically the "sub" claim from the JWT.
     *
     * @return the principal identifier
     */
    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    /**
     * Returns the underlying {@link AuthenticationContext} containing validated JWT claims.
     *
     * @return the authentication context
     */
    public AuthenticationContext getAuthenticationContext() {
        return authenticationContext;
    }
}
