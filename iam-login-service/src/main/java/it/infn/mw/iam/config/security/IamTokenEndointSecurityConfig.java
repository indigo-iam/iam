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

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import it.infn.mw.iam.core.client.ClientUserDetailsService;
import it.infn.mw.iam.core.oauth.TokenEndpointJwtClientAuthFilter;

@SuppressWarnings("deprecation")
@Configuration
@Order(-1)
public class IamTokenEndointSecurityConfig extends WebSecurityConfigurerAdapter {

  public static final String TOKEN_ENDPOINT = "/token";

  @Autowired
  private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

  @Autowired
  @Qualifier("clientUserDetailsService")
  private ClientUserDetailsService userDetailsService;

  @Autowired
  private TokenEndpointJwtClientAuthFilter jwtClientAuthFilter;

  @Autowired
  private ClientCredentialsTokenEndpointFilter ccFilter;

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {

    DaoAuthenticationProvider provider = new DaoAuthenticationProvider() {

      @Override
      public Authentication authenticate(Authentication authentication)
          throws AuthenticationException {

        String clientId = authentication.getName();
        ClientDetailsEntity client = null;
        try {
          client = userDetailsService.getClientDetailsService().loadClientByClientId(clientId);
        } catch (InvalidClientException e) {
          throw new BadCredentialsException(e.getMessage());
        }

        if (AuthMethod.NONE.equals(client.getTokenEndpointAuthMethod())
            && client.getClientSecret() != null) {
          throw new AuthenticationServiceException("Public client requires no secret");
        }
        if (!supportsBasic(client)) {
          throw new BadCredentialsException("Client does not support basic authentication");
        }

        return super.authenticate(authentication);
      }

      private boolean supportsBasic(ClientDetailsEntity c) {
        return AuthMethod.SECRET_BASIC.equals(c.getTokenEndpointAuthMethod())
            || AuthMethod.NONE.equals(c.getTokenEndpointAuthMethod());
      }
    };

    provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
    provider.setUserDetailsService(userDetailsService);

    auth.authenticationProvider(provider);
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

      .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

      .cors(Customizer.withDefaults())

      .csrf(csrf -> csrf.disable());

  }
}
