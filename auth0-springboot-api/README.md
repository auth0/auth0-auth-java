A Springboot library that provides **everything the standard Spring Security JWT Bearer authentication offers**, with the added power of **built-in DPoP (Demonstration of Proof-of-Possession)** support for enhanced token security. Simplify your Auth0 JWT authentication integration for Spring Boot APIs with Auth0-specific configuration and validation.

## Features

This library builds on top of the standard Spring Security JWT authentication, providing:

- **Complete Spring Security JWT Functionality** - All features from Spring Security JWT Bearer are available
- **Built-in DPoP Support** - Industry-leading proof-of-possession token security per [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- **Multi-Custom Domain (MCD) Support** - Validate tokens from multiple Auth0 custom domains with static lists or dynamic resolution
- **Extensible Caching** - Pluggable `AuthCache` interface for OIDC discovery and JWKS caching with distributed backend support (Redis, Memcached)
- **Auto-Configuration** - Spring Boot auto-configuration with minimal setup
- **Flexible Authentication Modes** - Bearer-only, DPoP-only, or flexible mode supporting both

## Requirements

- This library currently supports **Java 8+** for core functionality
- **Spring Boot 3.2+** (requires Java 17+) for Spring Boot integration

## Getting Started

### Installation

Add the dependency via Maven:

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>auth0-springboot-api</artifactId>
    <version>1.0.0</version>
</dependency>
```

or Gradle:

```gradle
dependencies {
    implementation 'com.auth0:auth0-springboot-api:1.0.0'
}
```

### Configure the SDK

Add Auth0 authentication to your Spring Boot API:

**1. Configure Auth0 properties in `application.yml`:**

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://your-api-identifier"
```

**2. Create a Security Configuration class:**

```java
import com.auth0.spring.boot.Auth0AuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http, Auth0AuthenticationFilter authFilter) throws Exception {
        return http.csrf(csrf -> csrf.disable())
                   .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                   .authorizeHttpRequests(auth -> auth
                       .requestMatchers("/api/protected").authenticated()
                       .anyRequest().permitAll())
                   .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
                   .build();
    }
}
```

**3. Create your API endpoints:**

```java
@RestController
public class ApiController {

    @GetMapping("/open-endpoint")
    public ResponseEntity<String> openEndpoint() {
        return ResponseEntity.ok("This endpoint is available to all users.");
    }

    @GetMapping("/api/protected")
    public ResponseEntity<String> protectedEndpoint(Authentication authentication) {
        String userId = authentication.getName();
        return ResponseEntity.ok("Hello, authenticated user: " + userId);
    }
}
```

That's it! Your API now validates JWT tokens from Auth0.

**Note** - If authorization header is null for protected endpoints, WWW-Authenticate header in response is not added.

### Configuration Options

**Required Settings:**

- **Domain**: Your Auth0 domain (e.g., `my-app.auth0.com`) - **without** the `https://` prefix
- **Audience**: The API identifier configured in your Auth0 Dashboard

**Optional Settings:**

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://your-api-identifier"
  dpopMode: ALLOWED # DISABLED, ALLOWED (default), REQUIRED
  dpopIatOffsetSeconds: 300 # 300 s (default)
  dpopIatLeewaySeconds: 30 # 30s (default)
```

## DPoP: Enhanced Token Security

**DPoP (Demonstration of Proof-of-Possession)** is a security mechanism that binds access tokens to a cryptographic key, making them resistant to token theft and replay attacks. This library provides seamless DPoP integration for your Auth0-protected APIs.

**Learn more about DPoP:** [Auth0 DPoP Documentation](https://auth0.com/docs/secure/sender-constraining/demonstrating-proof-of-possession-dpop)

### Enabling DPoP

Enable DPoP by setting the mode in your configuration:

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://your-api-identifier"
  dpopMode: ALLOWED # Enable DPoP support while maintaining Bearer token compatibility
```

That's it! Your API now supports DPoP tokens while maintaining backward compatibility with Bearer tokens.

### DPoP Configuration Options

For fine-grained control, configure DPoP behavior:

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://your-api-identifier"
  dpopMode: REQUIRED # Only accept DPoP tokens
  dpopIatOffsetSeconds: 300 # Allow 300 seconds offset for 'iat' claim (default)
  dpopIatLeewaySeconds: 30 # 30 seconds leeway for time-based validation (default)
```

### DPoP Modes

Choose the right enforcement mode for your security requirements:

| Mode                  | Description                                   |
| --------------------- | --------------------------------------------- |
| `ALLOWED` _(default)_ | Accept both DPoP and Bearer tokens            |
| `REQUIRED`            | Only accept DPoP tokens, reject Bearer tokens |
| `DISABLED`            | Standard JWT Bearer validation only           |

**Example client requests:**

**Bearer Token (traditional):**

```bash
curl -H "Authorization: Bearer <jwt_token>" \
     https://your-api.example.com/api/protected
```

**DPoP Token (enhanced security):**

```bash
curl -H "Authorization: DPoP <jwt_token>" \
     -H "DPoP: <dpop_proof>" \
     https://your-api.example.com/api/protected
```

## Multi-Custom Domain (MCD) Support

For tenants with multiple custom domains, the SDK can validate tokens from any of the configured issuers. There are three ways to configure domain resolution:

### Option 1: Static Domain List

Configure a list of allowed issuer domains in `application.yml`:

```yaml
auth0:
  audience: "https://your-api-identifier"
  domains:
    - "login.acme.com"
    - "auth.partner.com"
    - "dev.example.com"
```

You can also set a primary domain alongside the list:

```yaml
auth0:
  domain: "primary.auth0.com"
  audience: "https://your-api-identifier"
  domains:
    - "login.acme.com"
    - "auth.partner.com"
```

### Option 2: Dynamic Domain Resolver

For scenarios where the allowed issuers depend on runtime context (e.g., tenant headers, database lookups), define a `DomainResolver` bean:

```java
import com.auth0.DomainResolver;

@Configuration
public class McdConfig {

    @Bean
    public DomainResolver domainResolver(TenantService tenantService) {
        return context -> {
            // context.getHeaders() — request headers (lowercase keys)
            // context.getUrl() — the API request URL
            // context.getTokenIssuer() — unverified iss claim (routing hint only)
            String tenantId = context.getHeaders().get("x-tenant-id");
            String domain = tenantService.getDomain(tenantId);
            return Collections.singletonList(domain);
        };
    }
}
```

When a `DomainResolver` bean is present, it takes precedence over the static `auth0.domains` list. The single `auth0.domain` can still coexist as a fallback.

### Option 3: Single Domain (Default)

For single-tenant setups, just use the `auth0.domain` property:

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://your-api-identifier"
```

## Extensibility

### Custom Cache Implementation

The SDK caches OIDC discovery metadata and JWKS providers using a unified cache with key prefixes (`discovery:{issuerUrl}` and `jwks:{jwksUri}`). By default, it uses a thread-safe in-memory LRU cache.

You can replace this with a distributed cache (Redis, Memcached, etc.) by implementing the `AuthCache` interface:

```java
import com.auth0.AuthCache;

public class RedisAuthCache implements AuthCache<Object> {

    private final RedisTemplate<String, Object> redisTemplate;
    private final Duration ttl;

    public RedisAuthCache(RedisTemplate<String, Object> redisTemplate, Duration ttl) {
        this.redisTemplate = redisTemplate;
        this.ttl = ttl;
    }

    @Override
    public Object get(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    @Override
    public void put(String key, Object value) {
        redisTemplate.opsForValue().set(key, value, ttl);
    }

    @Override
    public void remove(String key) {
        redisTemplate.delete(key);
    }

    @Override
    public void clear() {
        Set<String> keys = redisTemplate.keys("discovery:*");
        if (keys != null) redisTemplate.delete(keys);
        keys = redisTemplate.keys("jwks:*");
        if (keys != null) redisTemplate.delete(keys);
    }

    @Override
    public int size() {
        return 0; // approximate
    }
}
```

Then define it as a Spring bean — the auto-configuration picks it up automatically and wires it into `AuthOptions`. No need to create your own `AuthClient` bean:

```java
@Configuration
public class CacheConfig {

    @Bean
    public AuthCache<Object> authCache(RedisTemplate<String, Object> redisTemplate) {
        return new RedisAuthCache(redisTemplate, Duration.ofMinutes(10));
    }
}
```

When an `AuthCache` bean is present, the `cacheMaxEntries` and `cacheTtlSeconds` YAML properties are ignored — your implementation controls its own eviction and TTL.

### Default Cache Settings

If no custom cache is provided, the built-in in-memory cache is used with these defaults:

```yaml
auth0:
  cacheMaxEntries: 100   # max entries before LRU eviction
  cacheTtlSeconds: 600   # 10-minute TTL per entry
```

## Advanced Features

### Manual JWT Validation

For scenarios requiring manual token validation, inject and use the `AuthClient`:

```java
@RestController
public class CustomController {

    @Autowired
    private AuthClient authClient;

    @PostMapping("/api/custom-validation")
    public ResponseEntity<String> customValidation(HttpServletRequest request) {
        try {
            // Extract headers and request info
            Map<String, String> headers = extractHeaders(request);
            HttpRequestInfo requestInfo = new HttpRequestInfo(
                request.getMethod(),
                request.getRequestURL().toString(),
                null
            );

            // Manual validation
            AuthenticationContext context = authClient.verifyRequest(headers, requestInfo);
            String userId = (String) context.getClaims().get("sub");

            return ResponseEntity.ok("Token valid for user: " + userId);

        } catch (BaseAuthException e) {
            return ResponseEntity.status(401).body("Authentication failed: " + e.getMessage());
        }
    }

    private Map<String, String> extractHeaders(HttpServletRequest request) {
        Map<String, String> headers = new HashMap<>();
        Collections.list(request.getHeaderNames()).forEach(headerName ->
            headers.put(headerName, request.getHeader(headerName))
        );
        return headers;
    }
}
```

### Custom Claim Validation

Access JWT claims directly through `Auth0AuthenticationToken`'s clean API:

```java
@RestController
public class UserController {

    @GetMapping("/api/user-profile")
    public ResponseEntity<Map<String, Object>> userProfile(Authentication authentication) {
        // Cast to Auth0AuthenticationToken to access Auth0-specific features
        Auth0AuthenticationToken auth0Token = (Auth0AuthenticationToken) authentication;

        Map<String, Object> profile = new HashMap<>();
        profile.put("userId", auth0Token.getClaim("sub"));
        profile.put("email", auth0Token.getClaim("email"));
        profile.put("scopes", auth0Token.getScopes()); // Set<String> of scopes
        profile.put("authorities", authentication.getAuthorities()); // Spring Security authorities

        return ResponseEntity.ok(profile);
    }

    @GetMapping("/api/admin")
    public ResponseEntity<String> adminEndpoint(Authentication authentication) {
        // Validate custom claims using individual claim access
        Auth0AuthenticationToken auth0Token = (Auth0AuthenticationToken) authentication;

        String userRole = (String) auth0Token.getClaim("role");
        if ("admin".equals(userRole)) {
            return ResponseEntity.ok("Admin access granted");
        } else {
            return ResponseEntity.status(403).body("Admin role required");
        }
    }
}
```

### Scope-Based Authorization

Implement scope-based access control:

```java
@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http, Auth0AuthenticationFilter authFilter) throws Exception {
        return http.csrf(csrf -> csrf.disable())
                   .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                   .authorizeHttpRequests(auth -> auth
                       .requestMatchers("/api/admin/**").authenticated()
                           .requestMatchers("/api/users/**").hasAnyAuthority("SCOPE_read:messages")
                           .requestMatchers("/api/protected").authenticated()
                       .anyRequest().permitAll())
                   .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
                   .build();
    }
}
```


For custom scope validation in controllers:

```java
@Component
public class ScopeValidator {
    public boolean hasRequiredScopes(Authentication authentication, String... requiredScopes) {
        if (!(authentication instanceof Auth0AuthenticationToken)) {
            return false;
        }
        Auth0AuthenticationToken auth0Token = (Auth0AuthenticationToken) authentication;

        Set<String> tokenScopes = auth0Token.getScopes();
        return tokenScopes.containsAll(Arrays.asList(requiredScopes));
    }
}

@RestController
public class AdminController {

    @Autowired
    private ScopeValidator scopeValidator;

    @GetMapping("/api/admin")
    public ResponseEntity<Map<String, Object>> adminEndpoint(Authentication authentication) {
        if (!scopeValidator.hasRequiredScopes(authentication, "admin")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "insufficient_scope"));
        }
        return ResponseEntity.ok(Map.of("message", "Admin access granted"));
    }
}
```


## Examples

For comprehensive examples and use cases, see the playground application:

### Basic Endpoint Protection

```java
@RestController
public class ApiController {

    @GetMapping("/open")
    public String openEndpoint() {
        return "This endpoint is available to all users.";
    }

    @GetMapping("/protected")
    public String protectedEndpoint(Authentication auth) {
        return "Hello, " + auth.getName() + "!";
    }
}
```

### Claims-Based Logic

```java
@GetMapping("/conditional")
public ResponseEntity<String> conditionalEndpoint(Authentication authentication) {
   Auth0AuthenticationToken auth0Token = (Auth0AuthenticationToken) authentication;

   String userRole = (String) auth0Token.getClaim("role");
   if ("admin".equals(userRole)) {
      return ResponseEntity.ok("Admin access granted");
   } else {
      return ResponseEntity.status(403).body("Admin access required");
   }
}
```

## Development

### Building the Project

Clone the repository and build the project:

```bash
git clone https://github.com/auth0/auth0-auth-java.git
cd auth0-auth-java
./gradlew clean build
```

### Playground Application

The repository includes a playground application for testing both standard JWT Bearer and **DPoP authentication**:

#### Setup

1. **Configure Auth0 settings** in `auth0-springboot-api-playground/src/main/resources/application.yml`:

   ```yaml
   auth0:
     domain: "your-tenant.auth0.com"
     audience: "https://your-api-identifier"
     dpopMode: ALLOWED
   ```

2. **Run the playground**:

   ```bash
   ./gradlew :auth0-springboot-api-playground:bootRun
   ```

3. **Access the application**:
   - Application: `http://localhost:8080`
   - Open endpoint: GET `/open-endpoint` (no authentication required)
   - Protected endpoint: GET `/api/protected` (requires authentication)

#### Testing Authentication

**1. Obtain a JWT token from Auth0:**

```bash
curl -X POST https://your-tenant.auth0.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "audience": "https://your-api-identifier",
    "grant_type": "client_credentials"
  }'
```

**2. Test Bearer authentication:**

```bash
curl -H "Authorization: Bearer <your-jwt-token>" \
     http://localhost:8080/api/protected
```

**3. Test DPoP authentication** (requires DPoP-bound token):

```bash
curl -H "Authorization: DPoP <your-dpop-bound-token>" \
     -H "DPoP: <your-dpop-proof>" \
     http://localhost:8080/api/protected
```

## Contributing

We appreciate your contributions! Please review our contribution guidelines before submitting pull requests.

### Contribution Checklist

- Read the [Auth0 General Contribution Guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- Read the [Auth0 Code of Conduct](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- Ensure all tests pass
- Add tests for new functionality
- Update documentation as needed
- Sign all commits

## Support

If you have questions or need help:

- Check the [Auth0 Documentation](https://auth0.com/docs)
- Visit the [Auth0 Community](https://community.auth0.com/)
- Report issues on [GitHub Issues](https://github.com/auth0/auth0-auth-java/issues)

## License

Copyright 2025 Okta, Inc.
This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
Authors
Okta Inc.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">Auth0 is an easy-to-implement, adaptable authentication and authorization platform. To learn more check out <a href="https://auth0.com/why-auth0">Why Auth0?</a></p>
<p align="center">This project is licensed under the Apache License 2.0. See the <a href="../LICENSE">LICENSE</a> file for more info.</p>
