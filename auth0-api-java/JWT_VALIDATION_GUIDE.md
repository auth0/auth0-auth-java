# JWT Validation with Auth0 Java SDK

This document demonstrates how to use the JWT validation functionality in the auth0-api-java module.

## Overview

The `JWTValidator` class provides comprehensive JWT token validation using:

- **java-jwt**: For creating, decoding, and verifying JWTs
- **jwks-rsa**: For retrieving RSA public keys from JWKS endpoints

## Quick Start

### 1. Basic JWT Validation

```java
import com.auth0.jwt.JWTValidator;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.exception.JWTValidationException;

// Initialize validator
JWTValidator validator = new JWTValidator("your-tenant.auth0.com", "https://your-api.example.com");

// Validate a JWT token
try {
    DecodedJWT jwt = validator.validateToken(jwtToken);
    System.out.println("Token valid! User: " + jwt.getSubject());
} catch (JWTValidationException e) {
    System.err.println("Invalid token: " + e.getMessage());
}
```

### 2. Validation with Scope Checking

```java
import java.util.Arrays;
import java.util.List;

List<String> requiredScopes = Arrays.asList("read:users", "write:users");

try {
    DecodedJWT jwt = validator.validateTokenWithScopes(jwtToken, requiredScopes);
    System.out.println("Token valid with required scopes!");
} catch (JWTValidationException e) {
    System.err.println("Token missing required scopes: " + e.getMessage());
}
```

### 3. Token Decoding Without Verification

```java
// Useful for inspecting token contents without verification
try {
    DecodedJWT jwt = validator.decodeToken(jwtToken);
    System.out.println("Token issuer: " + jwt.getIssuer());
    System.out.println("Token subject: " + jwt.getSubject());
    System.out.println("Token expires: " + jwt.getExpiresAt());
} catch (JWTValidationException e) {
    System.err.println("Cannot decode token: " + e.getMessage());
}
```

## Complete Validation Flow

The JWT validation follows this process:

1. **Decode token header** to extract the Key ID (`kid`)
2. **Fetch public key** from JWKS endpoint using the `kid`
3. **Create RSA256 algorithm** instance with the public key
4. **Build JWT verifier** with expected issuer and audience
5. **Verify signature and claims** of the token

```java
// This is what happens internally in validateToken():

// 1. Decode the token header and payload without verifying the signature
DecodedJWT decodedJWT = JWT.decode(token);
String kid = decodedJWT.getKeyId();

// 2. Fetch the public key using the 'kid' from the JWKS endpoint
Jwk jwk = jwkProvider.get(kid);
RSAPublicKey publicKey = (RSAPublicKey) jwk.getPublicKey();

// 3. Create an RSA256 algorithm instance using the public key
Algorithm algorithm = Algorithm.RSA256(publicKey, null);

// 4. Build verifier with the expected issuer
JWTVerifier verifier = JWT.require(algorithm)
                          .withIssuer(issuer)
                          .withAudience(audience)
                          .build();

// 5. Verify the token's signature and claims
DecodedJWT jwt = verifier.verify(token);
```

## Web Service Integration Example

### Middleware Pattern

```java
public class JWTAuthMiddleware {
    private final JWTValidator jwtValidator;

    public JWTAuthMiddleware(String domain, String audience) throws MalformedURLException {
        this.jwtValidator = new JWTValidator(domain, audience);
    }

    public DecodedJWT validateRequest(String authorizationHeader) throws JWTValidationException {
        // Extract JWT from "Bearer <token>" format
        String token = extractJWTFromAuthorizationHeader(authorizationHeader);
        if (token == null) {
            throw new JWTValidationException("Missing or invalid Authorization header");
        }

        return jwtValidator.validateToken(token);
    }

    private String extractJWTFromAuthorizationHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7); // Remove "Bearer " prefix
        }
        return null;
    }
}
```

### Usage in API Endpoints

```java
// In your API controller/service
JWTAuthMiddleware authMiddleware = new JWTAuthMiddleware("your-tenant.auth0.com", "https://your-api.com");

public void handleApiRequest(HttpServletRequest request) {
    try {
        String authHeader = request.getHeader("Authorization");
        DecodedJWT jwt = authMiddleware.validateRequest(authHeader);

        // Extract user information
        String userId = jwt.getSubject();
        String userEmail = jwt.getClaim("email").asString();

        // Proceed with business logic
        processRequest(userId, userEmail);

    } catch (JWTValidationException e) {
        // Return 401 Unauthorized
        response.sendError(401, "Invalid or expired token");
    }
}
```

## Error Handling

The `JWTValidator` throws `JWTValidationException` for various scenarios:

- **Missing Key ID**: Token header doesn't contain `kid` claim
- **Invalid Signature**: Token signature doesn't match JWKS public key
- **Expired Token**: Token `exp` claim is in the past
- **Invalid Issuer**: Token `iss` claim doesn't match expected issuer
- **Invalid Audience**: Token `aud` claim doesn't match expected audience
- **Missing Scopes**: Token doesn't contain required scopes in `scope` claim
- **JWKS Fetch Error**: Unable to retrieve public key from JWKS endpoint

## Testing

### Unit Tests

The project includes comprehensive unit tests in `JWTValidatorTest.java` that demonstrate:

- ✅ Successful token validation
- ✅ Scope-based validation
- ✅ Token decoding without verification
- ❌ Expired token handling
- ❌ Missing scope validation
- ❌ Invalid signature detection

### Running Tests

```bash
./gradlew test
```

### Test Output Examples

```
✅ Example 1: Successfully validated JWT token
   Token subject: test-user
   Token issuer: https://test-domain.auth0.com/
   Token audience: [https://api.example.com]

✅ Example 2: Successfully validated JWT token with scopes
   Token scopes: read:users write:users admin:system
   Required scopes: [read:users, write:users]

❌ Example 4: Correctly rejected expired token
   Error message: JWT verification failed: The Token has expired on...
```

## Configuration

### Environment Setup

1. **Add Dependencies** (already added to `build.gradle`):

   ```gradle
   implementation 'com.auth0:java-jwt:4.4.0'
   implementation 'com.auth0:jwks-rsa:0.22.1'
   ```

2. **Configure Auth0 Settings**:

   - Domain: Your Auth0 tenant domain (e.g., `your-tenant.auth0.com`)
   - Audience: Your API identifier (configured in Auth0 Dashboard)

3. **Initialize Validator**:
   ```java
   JWTValidator validator = new JWTValidator(domain, audience);
   ```

### Custom JWKS Provider

For advanced scenarios, you can provide a custom JWKS provider:

```java
JwkProvider customProvider = new UrlJwkProvider(new URL("https://custom-jwks-url/.well-known/jwks.json"));
JWTValidator validator = new JWTValidator(issuer, audience, customProvider);
```

## Best Practices

1. **Cache Validator Instance**: Create validator once and reuse it
2. **Handle Exceptions**: Always wrap validation in try-catch blocks
3. **Validate Scopes**: Check required permissions for each API endpoint
4. **Log Validation Events**: Log both successful and failed validations
5. **Token Extraction**: Always validate Authorization header format
6. **Performance**: The JWKS provider caches public keys automatically

## Security Considerations

- ✅ Always validate tokens on the server side
- ✅ Use HTTPS for all JWKS endpoint communications
- ✅ Verify issuer and audience claims match your configuration
- ✅ Check token expiration times
- ✅ Validate required scopes for API access
- ❌ Never trust client-side token validation alone
- ❌ Don't expose sensitive information in JWT claims
