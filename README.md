# Auth0 Springboot Authentication Library

![Auth0 API SDK for securing your Java API Server using tokens from Auth0](https://cdn.auth0.com/website/sdks/banners/auth0-springboot-api-banner.png)

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/atko-cic/auth0-auth-java/actions)
![Java Version](https://img.shields.io/badge/java-8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A comprehensive Java library for Auth0 JWT authentication with built-in **DPoP (Demonstration of Proof-of-Possession)** support. This multi-module project provides both a core authentication library and Spring Boot integration for secure API development.

## 🏗️ Architecture Overview

This repository contains multiple modules designed for different use cases:

### Core Modules

| Module                                                                    | Description                                   | Java Version |
| ------------------------------------------------------------------------- | --------------------------------------------- | ------------ |
| **[auth0-springboot-api](./auth0-springboot-api/)**                       | Spring Boot auto-configuration and filters    | Java 17+     |
| **[auth0-springboot-api-playground](./auth0-springboot-api-playground/)** | Working example application                   | Java 17+     |

### Module Relationship

```
auth0-springboot-api (Published)
    ↳ bundles auth0-api-java (Internal - not published separately)
    ↳ examples in auth0-springboot-api-playground
```

## Getting Started

### For Spring Boot Applications (Recommended)

If you're building a Spring Boot application, use the Spring Boot integration:

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>auth0-springboot-api</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

**👉 [Get started with Spring Boot integration →](./auth0-springboot-api/README.md)**

### For Core Java Applications

The core library (`auth0-api-java`) is currently an internal module used by the Spring Boot integration. It provides:

- JWT validation with Auth0 JWKS integration
- DPoP proof validation per [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- Flexible authentication strategies


## 📚 Documentation

- **[Spring Boot Integration Guide](./auth0-springboot-api/README.md)** - Complete setup and usage guide
- **[Spring Boot Examples](./auth0-springboot-api/EXAMPLES.md)** - Code examples and patterns
- **[Playground Application](./auth0-springboot-api-playground/)** - Running example

## 🛠️ Development

This project uses Gradle with a multi-module setup:

```bash
# Build all modules
./gradlew build

# Build module
./gradlew :auth0-springboot-api:build

# Run tests
./gradlew test

# Run playground application
./gradlew :auth0-springboot-api-playground:bootRun
```

## 📦 Publishing

Only the Spring Boot integration module is published as a public artifact:

| Module                 | Group ID    | Artifact ID            | Version          | Status           |
| ---------------------- | ----------- | ---------------------- | ---------------- | ---------------- |
| `auth0-springboot-api` | `com.auth0` | `auth0-springboot-api` | `1.0.0-SNAPSHOT` | 📦 **Published** |

The core library (`auth0-api-java`) is bundled as an internal dependency within the Spring Boot module and is not published separately.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes in the appropriate module
4. Add tests for new functionality
5. Ensure all tests pass: `./gradlew test`
6. Ensure your commits are signed
7. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/atko-cic/auth0-auth-java/issues)
- **Documentation**: [Auth0 Documentation](https://auth0.com/docs)
- **Community**: [Auth0 Community](https://community.auth0.com/)

---

**🎯 New to Auth0?** [Sign up for a free Auth0 account →](https://auth0.com/signup)