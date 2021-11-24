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

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import it.infn.mw.iam.api.proxy.ProxyCertificatesApiController;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.FormClientCredentialsAuthenticationFilter;

@SuppressWarnings("deprecation")
@Configuration
public class IamApiSecurityConfig {

  @Configuration
  @Order(20)
  public static class IamProxyCertificateApiConfig extends WebSecurityConfigurerAdapter {
    private static final String PROXY_API_MATCHER =
        ProxyCertificatesApiController.PROXY_API_PATH + "/**";

    @Autowired
    private OAuth2AuthenticationProcessingFilter resourceFilter;

    @Autowired
    @Qualifier("clientUserDetailsService")
    private UserDetailsService userDetailsService;

    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
      auth.userDetailsService(userDetailsService)
        .passwordEncoder(NoOpPasswordEncoder.getInstance());
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      FormClientCredentialsAuthenticationFilter ccFilter =
          new FormClientCredentialsAuthenticationFilter(PROXY_API_MATCHER,
              authenticationEntryPoint);

      ccFilter.setAuthenticationManager(authenticationManager());

      // @formatter:off
      http.antMatcher(PROXY_API_MATCHER)
          .exceptionHandling()
            .authenticationEntryPoint(authenticationEntryPoint)
            .accessDeniedHandler(new OAuth2AccessDeniedHandler())
        .and()
          .addFilterBefore(ccFilter, SecurityContextPersistenceFilter.class)
          .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)
        .cors()
        .and()
        .sessionManagement()
          .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
          .authorizeRequests()
            .anyRequest().fullyAuthenticated()            
        .and()
          .csrf().disable();
      // @formatter:on
    }
  }

  @Configuration
  @Order(21)
  public static class IamApiConfig extends WebSecurityConfigurerAdapter {

    private static final String AUP_PATH = "/iam/aup";

    @Autowired
    private OAuth2AuthenticationProcessingFilter resourceFilter;

    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
      // @formatter:off
      http.requestMatchers()
        .antMatchers("/scim/**", 
            "/registration/**", 
            "/iam/**")
        .and()
          .exceptionHandling()
            .authenticationEntryPoint(authenticationEntryPoint)
            .accessDeniedHandler(new OAuth2AccessDeniedHandler())
        .and()
          .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)
        .cors()
        .and()
        .sessionManagement()
          .sessionCreationPolicy(SessionCreationPolicy.NEVER)
        .and()
          .authorizeRequests()
            .antMatchers("/iam/password-reset/**").permitAll()
            .antMatchers(POST, "/iam/authenticator-app/**").permitAll()
            .antMatchers(POST, "/registration/create").permitAll()
            .antMatchers(GET, "/registration/insufficient-auth").permitAll()
            .antMatchers(GET, "/registration/username-available/**").permitAll()
            .antMatchers(GET, "/registration/email-available/**").permitAll()
            .antMatchers(GET, "/registration/config").permitAll()
            .antMatchers(GET, "/registration/confirm/**").permitAll()
            .antMatchers(GET, "/registration/verify/**").permitAll()
            .antMatchers(GET, "/registration/submitted").permitAll()
            .antMatchers(GET, "/iam/config/**").permitAll()
            .antMatchers(GET, AUP_PATH).permitAll()
            .anyRequest().authenticated()
        .and()
          .csrf().disable();
      // @formatter:on
    }
  }

  @Configuration
  @Order(25)
  public static class ActuatorEndpointsConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private IamProperties properties;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
      // @formatter:off
      auth.inMemoryAuthentication()
        .withUser(properties.getActuatorUser().getUsername()).password(
            passwordEncoder.encode(
            properties.getActuatorUser().getPassword()))
        .roles("ACTUATOR");
      // @formatter:on
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
      http.requestMatcher(EndpointRequest.to(HealthEndpoint.class, InfoEndpoint.class))
        .httpBasic()
        .and()
        .authorizeRequests(r -> r.anyRequest().permitAll())
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .httpBasic();
    }
  }
}
