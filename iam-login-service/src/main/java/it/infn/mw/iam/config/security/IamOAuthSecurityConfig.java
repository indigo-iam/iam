/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.config.security;

import static org.springframework.http.HttpMethod.OPTIONS;
import static org.springframework.security.config.http.SessionCreationPolicy.NEVER;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import it.infn.mw.iam.api.client.registration.ClientRegistrationApiController;
import it.infn.mw.iam.core.authn.TokenEndpointBasicAuthenticationProvider;
import it.infn.mw.iam.core.client.IamSha256PasswordEncoder;
import it.infn.mw.iam.core.oauth.TokenEndpointJwtClientAuthFilter;

@SuppressWarnings("deprecation")
@Configuration
public class IamOAuthSecurityConfig {

  @Configuration
  @Order(-1)
  public class IamTokenEndointSecurityConfig extends WebSecurityConfigurerAdapter {

    public static final String TOKEN_ENDPOINT = "/token";

    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;
    private TokenEndpointJwtClientAuthFilter jwtClientAuthFilter;
    private ClientCredentialsTokenEndpointFilter ccFilter;
    private TokenEndpointBasicAuthenticationProvider basicAuthProvider;

    public IamTokenEndointSecurityConfig(OAuth2AuthenticationEntryPoint authenticationEntryPoint,
        TokenEndpointJwtClientAuthFilter jwtClientAuthFilter,
        ClientCredentialsTokenEndpointFilter ccFilter,
        TokenEndpointBasicAuthenticationProvider basicAuthProvider) {

      this.authenticationEntryPoint = authenticationEntryPoint;
      this.jwtClientAuthFilter = jwtClientAuthFilter;
      this.ccFilter = ccFilter;
      this.basicAuthProvider = basicAuthProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

      auth.authenticationProvider(basicAuthProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

      http.antMatcher(TOKEN_ENDPOINT)

        .httpBasic(httpBasic -> httpBasic.authenticationEntryPoint(authenticationEntryPoint))

        .authorizeRequests(auth -> auth.antMatchers(OPTIONS, TOKEN_ENDPOINT)
          .permitAll()
          .antMatchers(TOKEN_ENDPOINT)
          .authenticated())

        .addFilterBefore(jwtClientAuthFilter, AbstractPreAuthenticatedProcessingFilter.class)

        .addFilterAfter(ccFilter, BasicAuthenticationFilter.class)

        .exceptionHandling(ex -> ex.authenticationEntryPoint(authenticationEntryPoint)
          .accessDeniedHandler(new OAuth2AccessDeniedHandler()))

        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

        .cors(Customizer.withDefaults())

        .csrf(csrf -> csrf.disable());
    }
  }

  @Configuration
  @Order(12)
  public static class RegisterEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    public static final String REGISTER_ENDPOINT_PATTERN =
        ClientRegistrationApiController.ENDPOINT + "/**";

    private OAuth2AuthenticationProcessingFilter resourceFilter;
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    public RegisterEndpointAuthorizationConfig(OAuth2AuthenticationProcessingFilter resourceFilter,
        OAuth2AuthenticationEntryPoint authenticationEntryPoint) {

      this.resourceFilter = resourceFilter;
      this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    public void configure(final HttpSecurity http) throws Exception {

      http.requestMatchers(matchers -> matchers.antMatchers(REGISTER_ENDPOINT_PATTERN))

        .exceptionHandling(
            exceptions -> exceptions.authenticationEntryPoint(authenticationEntryPoint))

        .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)

        .sessionManagement(session -> session.sessionCreationPolicy(NEVER))

        .authorizeRequests(
            authorize -> authorize.antMatchers(REGISTER_ENDPOINT_PATTERN).permitAll())

        .csrf(csrf -> csrf.disable());
    }
  }

  @Configuration
  @Order(13)
  public static class UserInfoEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    private OAuth2AuthenticationProcessingFilter resourceFilter;
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    public UserInfoEndpointAuthorizationConfig(OAuth2AuthenticationProcessingFilter resourceFilter,
        OAuth2AuthenticationEntryPoint authenticationEntryPoint) {

      this.resourceFilter = resourceFilter;
      this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    public void configure(final HttpSecurity http) throws Exception {

      http.antMatcher("/userinfo**")

        .exceptionHandling(
            exceptions -> exceptions.authenticationEntryPoint(authenticationEntryPoint))

        .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)

        .cors(Customizer.withDefaults())

        .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))

        .csrf(csrf -> csrf.disable());
    }
  }

  @Configuration
  @Order(17)
  public static class JwkEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    private Http403ForbiddenEntryPoint http403ForbiddenEntryPoint;

    public JwkEndpointAuthorizationConfig(Http403ForbiddenEntryPoint http403ForbiddenEntryPoint) {

      this.http403ForbiddenEntryPoint = http403ForbiddenEntryPoint;
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      http.antMatcher("/jwk**")

        .exceptionHandling(
            exceptions -> exceptions.authenticationEntryPoint(http403ForbiddenEntryPoint))

        .cors(Customizer.withDefaults())

        .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))

        .authorizeRequests(authorize -> authorize.antMatchers("/**").permitAll());
    }
  }

  @Configuration
  @Order(27)
  public static class DeviceCodeEnpointConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      http.antMatcher("/devicecode")

        .csrf(csrf -> csrf.disable())

        .authorizeRequests(authorize -> authorize.anyRequest().permitAll())

        .sessionManagement(session -> session.sessionCreationPolicy(STATELESS));
    }
  }

  @Configuration
  @Order(28)
  public static class WellKnownEndpointConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      http.antMatcher("/.well-known/openid-configuration")

        .cors(Customizer.withDefaults())

        .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))

        .authorizeRequests(authorize -> authorize.antMatchers("/**").permitAll());
    }
  }

  @Configuration
  @Order(15)
  public static class IntrospectEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;
    private UserDetailsService userDetailsService;
    private TokenEndpointJwtClientAuthFilter jwtClientAuthFilter;

    public IntrospectEndpointAuthorizationConfig(
        OAuth2AuthenticationEntryPoint authenticationEntryPoint,
        @Qualifier("clientUserDetailsService") UserDetailsService userDetailsService,
        TokenEndpointJwtClientAuthFilter jwtClientAuthFilter) {

      this.authenticationEntryPoint = authenticationEntryPoint;
      this.userDetailsService = userDetailsService;
      this.jwtClientAuthFilter = jwtClientAuthFilter;
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {

      auth.userDetailsService(userDetailsService).passwordEncoder(new IamSha256PasswordEncoder());
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      http.antMatcher("/introspect/**")

        .csrf(csrf -> csrf.disable())

        .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))

        .exceptionHandling(
            exceptions -> exceptions.authenticationEntryPoint(authenticationEntryPoint))

        .cors(Customizer.withDefaults())

        .httpBasic(basic -> basic.authenticationEntryPoint(authenticationEntryPoint))

        .addFilterBefore(jwtClientAuthFilter, BasicAuthenticationFilter.class)

        .authorizeRequests(authorize -> authorize.anyRequest().fullyAuthenticated());
    }
  }

  @Configuration
  @Order(16)
  public static class RevokeEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;
    private UserDetailsService userDetailsService;

    public RevokeEndpointAuthorizationConfig(
        OAuth2AuthenticationEntryPoint authenticationEntryPoint,
        @Qualifier("clientUserDetailsService") UserDetailsService userDetailsService) {

      this.authenticationEntryPoint = authenticationEntryPoint;
      this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {

      auth.userDetailsService(userDetailsService).passwordEncoder(new IamSha256PasswordEncoder());
    }

    private ClientCredentialsTokenEndpointFilter clientCredentialsEndpointFilter()
        throws Exception {

      ClientCredentialsTokenEndpointFilter filter =
          new ClientCredentialsTokenEndpointFilter("/revoke");

      filter.setAuthenticationManager(authenticationManager());

      return filter;
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      http.antMatcher("/revoke**")

        .httpBasic(basic -> basic.authenticationEntryPoint(authenticationEntryPoint))

        .addFilterBefore(clientCredentialsEndpointFilter(), BasicAuthenticationFilter.class)

        .cors(Customizer.withDefaults())

        .exceptionHandling(
            exceptions -> exceptions.authenticationEntryPoint(authenticationEntryPoint))

        .csrf(csrf -> csrf.disable())

        .sessionManagement(session -> session.sessionCreationPolicy(STATELESS));
    }
  }
}
