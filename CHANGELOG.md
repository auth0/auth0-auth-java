# Changelog

## [1.0.0-beta.0](https://github.com/auth0/auth0-auth-java/tree/1.0.0-beta.0) (2026-03-02)

### Features

- **JWT Bearer Authentication** - Complete Spring Security integration for validating Auth0-issued JWTs.
- **DPoP (Demonstration of Proof-of-Possession) Support** - Built-in support for DPoP token security per [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449), including proof validation, token binding, and JWK thumbprint verification.
- **Flexible Authentication Modes** - Configure how your API handles token types:
  - `DISABLED` - Accept Bearer tokens only.
  - `ALLOWED` - Accept both Bearer and DPoP tokens (default).
  - `REQUIRED` - Enforce DPoP tokens only.
- **Scope-Based Authorization** - Derive Spring Security authorities from JWT scopes with `SCOPE_` prefix for use with `hasAuthority()`.
- **Custom Claim Access** - Access any JWT claim via `Auth0AuthenticationToken.getClaim(name)` and `getClaims()`.
- **Auto-Configuration** - Minimal setup required; just provide `auth0.domain` and `auth0.audience` properties.
- **WWW-Authenticate Header Generation** - Automatic RFC-compliant error response headers for Bearer and DPoP challenges.
- **Java 8+ Core Module** - The underlying `auth0-api-java` module targets Java 8, enabling use in non-Spring environments.

### Installation

**Gradle**

```groovy
implementation 'com.auth0:auth0-springboot-api:1.0.0-beta.0'
```

**Maven**

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>auth0-springboot-api</artifactId>
    <version>1.0.0-beta.0</version>
</dependency>
```

### Basic Usage

**1. Add application properties:**

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://your-api-identifier"
  dpopMode: ALLOWED                  # DISABLED | ALLOWED | REQUIRED
```

**2. Configure Spring Security:**

```java
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http, Auth0AuthenticationFilter authFilter)
            throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public").permitAll()
                .requestMatchers("/api/protected").authenticated()
                .requestMatchers("/api/admin/**").hasAuthority("SCOPE_admin")
                .anyRequest().permitAll())
            .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }
}
```

**3. Access authenticated user info in your controller:**

```java
@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/protected")
    public ResponseEntity<Map<String, Object>> protectedEndpoint(Authentication authentication) {
        Auth0AuthenticationToken token = (Auth0AuthenticationToken) authentication;
        return ResponseEntity.ok(Map.of(
            "user", authentication.getName(),
            "email", token.getClaim("email"),
            "scopes", token.getScopes()
        ));
    }
}
```

### Dependencies

| Dependency | Version | Module |
|---|---|---|
| Spring Boot Starter | 3.2.0 | auth0-springboot-api |
| Spring Boot Starter Web | 3.2.0 | auth0-springboot-api |
| Spring Boot Starter Security | 3.2.0 | auth0-springboot-api |
| Jackson Databind | 2.15.2 | auth0-api-java |
| Apache HttpClient | 4.5.14 | auth0-api-java |
| Auth0 java-jwt | 4.5.1 | auth0-api-java |
| Auth0 jwks-rsa | 0.23.0 | auth0-api-java |

**Runtime Requirements:**
- `auth0-springboot-api` — Java 17+
- `auth0-api-java` — Java 8+
