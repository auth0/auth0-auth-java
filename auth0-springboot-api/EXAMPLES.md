# Auth0 Spring Boot API Examples

This document provides examples for using the `auth0-springboot-api` package to validate Auth0 tokens in your Spring Boot applications.

## Basic Configuration

Configure your Auth0 settings in `application.yml`:

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://api.example.com"
```

Or in `application.properties`:

```properties
auth0.domain=your-tenant.auth0.com
auth0.audience=https://api.example.com
```

## Bearer Authentication

Bearer authentication is the standard OAuth 2.0 token authentication method.

### Basic Setup

```java
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain apiSecurity(
            HttpSecurity http,
            Auth0AuthenticationFilter authFilter
    ) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/api/public").permitAll()
                    .requestMatchers("/api/protected").authenticated()
                    .anyRequest().authenticated()
                )
                .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
```

### Protected Endpoint Example

```java
@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/protected")
    public ResponseEntity<Map<String, Object>> protectedEndpoint(Authentication authentication) {
        String userId = authentication.getName(); // Returns the 'sub' claim

        return ResponseEntity.ok(Map.of(
            "message", "Access granted!",
            "user", userId,
            "authenticated", true
        ));
    }

    @GetMapping("/public")
    public ResponseEntity<Map<String, Object>> publicEndpoint() {
        return ResponseEntity.ok(Map.of(
            "message", "Public endpoint - no token required"
        ));
    }
}
```

### Accessing Token Claims

```java
@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getUserProfile(Authentication authentication) {
        if (authentication instanceof Auth0AuthenticationToken auth0Token) {
            return ResponseEntity.ok(Map.of(
                "sub", String.valueOf(auth0Token.getClaim("sub")),
                "email", String.valueOf(auth0Token.getClaim("email")),
                "scope", String.valueOf(auth0Token.getClaim("scope")),
                "scopes", auth0Token.getScopes()
            ));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
```

## DPoP Authentication

[DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) (Demonstrating Proof of Possession) is an application-level mechanism for sender-constraining OAuth 2.0 access and refresh tokens.

### Configuration Modes

#### 1. Allowed Mode (Default)

Accepts both Bearer and DPoP tokens:

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://api.example.com"
  dpop-mode: ALLOWED
```

#### 2. Required Mode

Only accepts DPoP tokens:

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://api.example.com"
  dpop-mode: REQUIRED
```

#### 3. Disabled Mode

Only accepts Bearer tokens:

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://api.example.com"
  dpop-mode: DISABLED
```

### Advanced DPoP Configuration

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://api.example.com"
  dpop-mode: ALLOWED
  dpop-iat-offset-seconds: 300  # DPoP proof time window (default: 300)
  dpop-iat-leeway-seconds: 30   # DPoP proof time leeway (default: 30)
```

### How DPoP Works in Your Controllers

DPoP validation is handled entirely by the library at the filter level. Your controllers don't need any DPoP-specific code — the library validates the DPoP proof automatically before the request reaches your controller. A validated DPoP request produces the same `Auth0AuthenticationToken` as a Bearer request:

```java
@RestController
@RequestMapping("/api")
public class SensitiveDataController {

    @GetMapping("/sensitive")
    public ResponseEntity<Map<String, Object>> sensitiveEndpoint(Authentication authentication) {
        // This works the same whether the client used Bearer or DPoP.
        // DPoP proof validation already happened in the filter.
        if (authentication instanceof Auth0AuthenticationToken auth0Token) {
            return ResponseEntity.ok(Map.of(
                "user", authentication.getName(),
                "scopes", auth0Token.getScopes(),
                "message", "Access granted"
            ));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
```

The difference is in what the library **rejects**:
- `ALLOWED` mode: Accepts both `Authorization: Bearer <token>` and `Authorization: DPoP <token>` + `DPoP: <proof>`
- `REQUIRED` mode: Rejects Bearer tokens — only `DPoP` tokens with a valid proof are accepted
- `DISABLED` mode: Rejects DPoP tokens — only `Bearer` tokens are accepted

## Scope-Based Authorization

The library maps JWT scopes to Spring Security authorities with a `SCOPE_` prefix. For example, a token with `scope: "read:messages write:messages"` produces authorities `SCOPE_read:messages` and `SCOPE_write:messages`.

### Option 1: Security Filter Chain (Recommended)

The simplest approach — define scope requirements in your security configuration:

```java
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain apiSecurity(
            HttpSecurity http,
            Auth0AuthenticationFilter authFilter
    ) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/api/public").permitAll()
                    .requestMatchers("/api/admin/**").hasAuthority("SCOPE_admin")
                    .requestMatchers("/api/users/**").hasAuthority("SCOPE_read:users")
                    .anyRequest().authenticated()
                )
                .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
```

### Option 2: Method-Level Security with @PreAuthorize

For fine-grained control per method. Requires `@EnableMethodSecurity` on a configuration class:

```java
@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {
    // Enables @PreAuthorize annotations
}
```

```java
@RestController
@RequestMapping("/api/users")
public class UserManagementController {

    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_read:users')")
    public ResponseEntity<List<User>> getUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_write:users')")
    public ResponseEntity<User> createUser(@RequestBody User user) {
        return ResponseEntity.ok(userService.createUser(user));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('SCOPE_delete:users')")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
```

### Option 3: Programmatic Scope Check

Use `getScopes()` on the token directly when you need custom logic:

```java
@RestController
@RequestMapping("/api")
public class AdminController {

    @GetMapping("/admin")
    public ResponseEntity<Map<String, Object>> adminEndpoint(Authentication authentication) {
        if (authentication instanceof Auth0AuthenticationToken auth0Token) {
            Set<String> scopes = auth0Token.getScopes();

            if (!scopes.contains("admin") || !scopes.contains("read:admin")) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "insufficient_scope"));
            }

            return ResponseEntity.ok(Map.of("message", "Admin access granted"));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
```

## Configuration Reference

### Complete Configuration Example

```yaml
auth0:
  # Required: Your Auth0 domain
  domain: "your-tenant.auth0.com"

  # Required: API identifier/audience
  audience: "https://api.example.com"

  # Optional: DPoP mode (DISABLED, ALLOWED, REQUIRED)
  # Default: ALLOWED
  dpop-mode: ALLOWED

  # Optional: DPoP proof time window in seconds
  # Default: 300 (5 minutes)
  dpop-iat-offset-seconds: 300

  # Optional: DPoP proof time leeway in seconds
  # Default: 30 (30 seconds)
  dpop-iat-leeway-seconds: 30
```

### Environment Variables

You can also configure using environment variables:

```bash
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_AUDIENCE=https://api.example.com
AUTH0_DPOPMODE=ALLOWED
AUTH0_DPOPIATOFFSETSECONDS=300
AUTH0_DPOPIATLEEWAYSSECONDS=30
```

> **Note:** Spring Boot environment variable binding removes dashes and is case-insensitive. Do not use underscores to separate words within a property name (e.g., use `AUTH0_DPOPMODE`, not `AUTH0_DPOP_MODE`).

## Error Handling

### Common HTTP Status Codes

- **401 Unauthorized**: Missing or invalid token
- **403 Forbidden**: Valid token but insufficient permissions

### WWW-Authenticate Headers

The library automatically sets appropriate `WWW-Authenticate` headers on authentication failures:

```
# ALLOWED mode (default)
WWW-Authenticate: Bearer realm="api", DPoP algs="ES256"

# REQUIRED mode
WWW-Authenticate: DPoP algs="ES256"

# DPoP-specific errors
WWW-Authenticate: DPoP error="invalid_dpop_proof", error_description="DPoP proof validation failed"
```
