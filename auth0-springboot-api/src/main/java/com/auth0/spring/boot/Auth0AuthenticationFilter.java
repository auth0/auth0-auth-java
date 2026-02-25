package com.auth0.spring.boot;

import com.auth0.AuthClient;
import com.auth0.WWWAuthenticateBuilder;
import com.auth0.enums.DPoPMode;
import com.auth0.exception.BaseAuthException;
import com.auth0.exception.MissingAuthorizationException;
import com.auth0.models.AuthenticationContext;
import com.auth0.models.HttpRequestInfo;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

public class Auth0AuthenticationFilter extends OncePerRequestFilter {

  private final AuthClient authClient;

  private final Auth0Properties auth0Properties;

  public Auth0AuthenticationFilter(AuthClient authClient, Auth0Properties auth0Properties) {
    this.authClient = authClient;
    this.auth0Properties = auth0Properties;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {

    try {

      Map<String, String> headers = extractHeaders(request);

      String authorizationHeader = headers.get("authorization");
      if (authorizationHeader == null || authorizationHeader.trim().isEmpty()) {
        chain.doFilter(request, response);
        return;
      }

      HttpRequestInfo requestInfo = extractRequestInfo(request);

      AuthenticationContext ctx = authClient.verifyRequest(headers, requestInfo);

      Auth0AuthenticationToken authentication = new Auth0AuthenticationToken(ctx);
      authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

      SecurityContextHolder.getContext().setAuthentication(authentication);

      chain.doFilter(request, response);

    } catch (BaseAuthException ex) {
      response.setStatus(ex.getStatusCode());

      Map<String, String> exceptionHeaders = ex.getHeaders();
      String wwwAuthenticate = exceptionHeaders.get("WWW-Authenticate");

      if (wwwAuthenticate != null) {
        response.addHeader("WWW-Authenticate", wwwAuthenticate);
      }
      SecurityContextHolder.clearContext();
    }
  }

  Map<String, String> extractHeaders(HttpServletRequest request)
      throws MissingAuthorizationException {

    List<String> authHeaders = Collections.list(request.getHeaders("Authorization"));
    if (authHeaders != null && authHeaders.size() > 1) {
      String firstValue = authHeaders.get(0);

      MissingAuthorizationException ex = new MissingAuthorizationException();

      String[] parts = firstValue.trim().split("\\s+", 2);

      DPoPMode dpopMode = auth0Properties.getDpopMode();
      if (dpopMode == null) {
        dpopMode = DPoPMode.ALLOWED; // default fallback
      }

      List<String> challenges =
          WWWAuthenticateBuilder.buildChallenges(
              ex.getErrorCode(),
              ex.getErrorDescription(),
              dpopMode,
              parts[0].toLowerCase(Locale.ROOT));

      if (!challenges.isEmpty()) {
        ex.addHeader("WWW-Authenticate", String.join(", ", challenges));
      }

      throw ex;
    }

    Map<String, String> headers = new HashMap<>();
    Enumeration<String> names = request.getHeaderNames();

    if (names != null) {
      while (names.hasMoreElements()) {
        String name = names.nextElement();
        headers.put(name.toLowerCase(Locale.ROOT), request.getHeader(name));
      }
    }

    return headers;
  }

  HttpRequestInfo extractRequestInfo(HttpServletRequest request) {
    String htu = buildHtu(request);
    return new HttpRequestInfo(request.getMethod(), htu, null);
  }

  static String buildHtu(HttpServletRequest request) {
    String scheme = request.getScheme().toLowerCase(Locale.ROOT);
    String host = request.getServerName().toLowerCase(Locale.ROOT);

    int port = request.getServerPort();
    boolean defaultPort =
        (scheme.equals("http") && port == 80) || (scheme.equals("https") && port == 443);

    StringBuilder htu = new StringBuilder();
    htu.append(scheme).append("://").append(host);

    if (!defaultPort) {
      htu.append(":").append(port);
    }

    htu.append(request.getRequestURI());

    return htu.toString();
  }
}
