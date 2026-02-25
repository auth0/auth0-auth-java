package com.auth0.spring.boot;

import com.auth0.AuthClient;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@ConditionalOnClass(AuthClient.class)
public class Auth0SecurityAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public Auth0AuthenticationFilter authAuthenticationFilter(
      AuthClient authClient, Auth0Properties auth0Properties) {
    return new Auth0AuthenticationFilter(authClient, auth0Properties);
  }
}
