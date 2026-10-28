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

import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.HEAD;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import java.util.LinkedHashMap;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import it.infn.mw.iam.api.proxy.ProxyCertificatesApiController;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.security.IamWebSecurityConfig.UserLoginConfig;
import it.infn.mw.iam.config.security.filters.MtlsTokenBindingFilter;
import it.infn.mw.iam.core.client.IamSha256PasswordEncoder;
import it.infn.mw.iam.core.oauth.FormClientCredentialsAuthenticationFilter;

@SuppressWarnings("deprecation")
@Configuration
public class IamApplicationApiSecurityConfig {

  private static final String AUP_PATH = "/iam/aup";
  private static final String AUP_SIGN_PATH = "/iam/aup/sign";

  /*
   * These endpoints belong to dedicated protocol/browser chains.
   *
   * Keep the MFA matcher consistent with MultiFactorConfigurationAdapter.
   */
  private static final RequestMatcher DEDICATED_ENDPOINTS =
      new OrRequestMatcher(new AntPathRequestMatcher(MFA_VERIFY_URL + "**"),
          new AntPathRequestMatcher("/iam/api/oid-fed/client-registration"));

  private static final RequestMatcher API_PATHS =
      new AndRequestMatcher(
          new OrRequestMatcher(new AntPathRequestMatcher("/api/**"),
              new AntPathRequestMatcher("/scim/**"), new AntPathRequestMatcher("/registration/**"),
              new AntPathRequestMatcher("/iam/**")),
          new NegatedRequestMatcher(DEDICATED_ENDPOINTS));

  /*
   * This matcher only selects the chain. Authentication and token validation are performed by the
   * resource filter.
   */
  private static final RequestMatcher BEARER_HEADER = request -> {
    String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);

    return authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7);
  };

  private static final RequestMatcher BEARER_API_REQUEST =
      new AndRequestMatcher(API_PATHS, BEARER_HEADER);

  private static final RequestMatcher BROWSER_API_REQUEST =
      new AndRequestMatcher(API_PATHS, new NegatedRequestMatcher(BEARER_HEADER));

  @Configuration
  @Order(21)
  public static class BearerApiConfig extends WebSecurityConfigurerAdapter {

    private final OAuth2AuthenticationProcessingFilter resourceFilter;
    private final OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    public BearerApiConfig(
        @Qualifier("resourceServerFilter") OAuth2AuthenticationProcessingFilter resourceFilter,
        OAuth2AuthenticationEntryPoint authenticationEntryPoint) {

      this.resourceFilter = resourceFilter;
      this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

      http.requestMatcher(BEARER_API_REQUEST)

        .securityContext(
            context -> context.securityContextRepository(new NullSecurityContextRepository()))

        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

        .requestCache(cache -> cache.disable())

        .exceptionHandling(
            exceptions -> exceptions.authenticationEntryPoint(authenticationEntryPoint)
              .accessDeniedHandler(new OAuth2AccessDeniedHandler()))

        .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)

        .addFilterAfter(new MtlsTokenBindingFilter(), ExceptionTranslationFilter.class)

        .cors(Customizer.withDefaults())

        .authorizeRequests(authorize -> authorize.anyRequest().authenticated())

        .csrf(csrf -> csrf.disable());
    }
  }

  @Configuration
  @Order(22)
  public static class BrowserApiConfig extends WebSecurityConfigurerAdapter {

    private final OAuth2AuthenticationEntryPoint authenticationEntryPoint;
    private final CookieCsrfTokenRepository csrfTokenRepository;
    private final UserLoginConfig userLoginConfig;

    public BrowserApiConfig(OAuth2AuthenticationEntryPoint authenticationEntryPoint,
        CookieCsrfTokenRepository csrfTokenRepository, UserLoginConfig userLoginConfig) {

      this.authenticationEntryPoint = authenticationEntryPoint;
      this.csrfTokenRepository = csrfTokenRepository;
      this.userLoginConfig = userLoginConfig;
    }

    private AuthenticationEntryPoint browserApiEntryPoint() {

      LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();

      entryPoints.put(new AntPathRequestMatcher(AUP_SIGN_PATH), userLoginConfig.entryPoint());

      DelegatingAuthenticationEntryPoint entryPoint =
          new DelegatingAuthenticationEntryPoint(entryPoints);

      entryPoint.setDefaultEntryPoint(authenticationEntryPoint);

      return entryPoint;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

      http.requestMatcher(BROWSER_API_REQUEST)

        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.NEVER)
          .enableSessionUrlRewriting(false))

        .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(browserApiEntryPoint())
          .accessDeniedHandler(new OAuth2AccessDeniedHandler()))

        .cors(Customizer.withDefaults())

        .authorizeRequests(authorize -> authorize.antMatchers("/iam/password-reset/**")
          .permitAll()
          .antMatchers(POST, "/registration/create")
          .permitAll()
          .antMatchers(GET, "/registration/insufficient-auth")
          .permitAll()
          .antMatchers(GET, "/registration/username-available/**")
          .permitAll()
          .antMatchers(GET, "/registration/email-available/**")
          .permitAll()
          .antMatchers(GET, "/registration/config")
          .permitAll()
          .antMatchers(HEAD, "/registration/verify/**")
          .permitAll()
          .antMatchers(GET, "/registration/verify/**")
          .permitAll()
          .antMatchers(POST, "/registration/verify")
          .permitAll()
          .antMatchers(GET, "/registration/submitted")
          .permitAll()
          .antMatchers(GET, "/iam/config/**")
          .permitAll()
          .antMatchers(GET, AUP_PATH)
          .permitAll()
          .anyRequest()
          .authenticated())

        .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository));
    }
  }

  /*
   * Protected Resource Registration Endpoint
   */
  @Configuration
  @Order(11)
  public static class ResourceEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    private OAuth2AuthenticationProcessingFilter resourceFilter;
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    public ResourceEndpointAuthorizationConfig(OAuth2AuthenticationProcessingFilter resourceFilter,
        OAuth2AuthenticationEntryPoint authenticationEntryPoint) {
      this.resourceFilter = resourceFilter;
      this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    public void configure(final HttpSecurity http) throws Exception {

      http.antMatcher("/resource/**")

        .exceptionHandling(
            exceptions -> exceptions.authenticationEntryPoint(authenticationEntryPoint))

        .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)

        .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))

        .authorizeRequests(authorize -> authorize.antMatchers("/resource/**").permitAll())

        .csrf(csrf -> csrf.disable())

        .cors(Customizer.withDefaults());
    }
  }

  @Configuration
  @Order(20)
  public static class IamProxyCertificateApiConfig extends WebSecurityConfigurerAdapter {

    private static final String PROXY_API_MATCHER =
        ProxyCertificatesApiController.PROXY_API_PATH + "/**";

    private OAuth2AuthenticationProcessingFilter resourceFilter;
    private UserDetailsService userDetailsService;
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    public IamProxyCertificateApiConfig(OAuth2AuthenticationProcessingFilter resourceFilter,
        @Qualifier("clientUserDetailsService") UserDetailsService userDetailsService,
        OAuth2AuthenticationEntryPoint authenticationEntryPoint) {

      this.resourceFilter = resourceFilter;
      this.userDetailsService = userDetailsService;
      this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {

      auth.userDetailsService(userDetailsService).passwordEncoder(new IamSha256PasswordEncoder());
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      FormClientCredentialsAuthenticationFilter ccFilter =
          new FormClientCredentialsAuthenticationFilter(PROXY_API_MATCHER,
              authenticationEntryPoint);

      ccFilter.setAuthenticationManager(authenticationManager());

      http.antMatcher(PROXY_API_MATCHER)

        .exceptionHandling(
            exceptions -> exceptions.authenticationEntryPoint(authenticationEntryPoint)
              .accessDeniedHandler(new OAuth2AccessDeniedHandler()))

        .addFilterBefore(ccFilter, SecurityContextPersistenceFilter.class)

        .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)

        .cors(Customizer.withDefaults())

        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

        .authorizeRequests(authorize -> authorize.anyRequest().fullyAuthenticated())

        .csrf(csrf -> csrf.disable());
    }
  }

  @Configuration
  @Order(25)
  public static class ActuatorEndpointsConfig extends WebSecurityConfigurerAdapter {

    private IamProperties properties;
    private PasswordEncoder passwordEncoder;

    public ActuatorEndpointsConfig(IamProperties properties, PasswordEncoder passwordEncoder) {

      this.properties = properties;
      this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {

      auth.inMemoryAuthentication()
        .withUser(properties.getActuatorUser().getUsername())
        .password(passwordEncoder.encode(properties.getActuatorUser().getPassword()))
        .roles("ACTUATOR");
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      http.requestMatcher(EndpointRequest.to(HealthEndpoint.class, InfoEndpoint.class))

        .httpBasic(Customizer.withDefaults())

        .authorizeRequests(authorize -> authorize.anyRequest().permitAll())

        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    }
  }
}
