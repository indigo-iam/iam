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

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTHN_UNREGISTERED_USER_AUTH;
import static it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType.OIDC;
import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import java.time.Clock;
import java.util.Optional;

import javax.servlet.RequestDispatcher;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.authn.AARCHintService;
import it.infn.mw.iam.authn.AuthenticationSuccessHandlerHelper;
import it.infn.mw.iam.authn.CheckMultiFactorIsEnabledSuccessHandler;
import it.infn.mw.iam.authn.ExternalAuthenticationHintService;
import it.infn.mw.iam.authn.HintAwareAuthenticationEntryPoint;
import it.infn.mw.iam.authn.multi_factor_authentication.ExtendedAuthenticationFilter;
import it.infn.mw.iam.authn.multi_factor_authentication.ExtendedHttpServletRequestFilter;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorVerificationFilter;
import it.infn.mw.iam.authn.oidc.OIDCAuthenticationFilter;
import it.infn.mw.iam.authn.oidc.OIDCAuthenticationProvider;
import it.infn.mw.iam.authn.oidc.OidcLogoutSuccessHandler;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationProvider;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationUserDetailService;
import it.infn.mw.iam.authn.x509.IamX509PreauthenticationProcessingFilter;
import it.infn.mw.iam.authn.x509.X509AuthenticationCredentialExtractor;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.ExternalAuthAttributeSectionBehaviour;
import it.infn.mw.iam.config.IamProperties.RegistrationField;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.IamLocalAuthenticationProvider;
import it.infn.mw.iam.core.client.IamSha256PasswordEncoder;
import it.infn.mw.iam.core.oauth.TokenEndpointJwtClientAuthFilter;
import it.infn.mw.iam.core.oidc.AuthorizationRequestFilter;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.repository.IamX509CertificateRepository;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;

@SuppressWarnings("deprecation")
@Configuration
@EnableWebSecurity
public class IamWebSecurityConfig {

  @Configuration
  @Order(100)
  public static class UserLoginConfig extends WebSecurityConfigurerAdapter {

    @Value("${iam.baseUrl}")
    private String iamBaseUrl;

    @Autowired
    private OAuth2WebSecurityExpressionHandler oAuth2WebSecurityExpressionHandler;

    @Autowired
    private AuthorizationRequestFilter authorizationRequestFilter;

    @Autowired
    @Qualifier("iamUserDetailsService")
    private UserDetailsService iamUserDetailsService;

    @Autowired
    private X509AuthenticationCredentialExtractor x509CredentialExtractor;

    @Autowired
    private IamX509AuthenticationUserDetailService x509UserDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private IamX509CertificateRepository certRepo;

    @Autowired
    private IamTotpMfaService iamTotpMfaService;

    @Autowired
    private AUPSignatureCheckService aupSignatureCheckService;

    @Autowired
    private AccountUtils accountUtils;

    @Autowired
    private ExternalAuthenticationHintService hintService;

    @Autowired
    private AARCHintService aarcHintService;

    @Autowired
    private IamProperties iamProperties;

    @Autowired
    private IamTotpMfaProperties iamTotpMfaProperties;

    @Autowired
    private OidcLogoutSuccessHandler oidcLogoutSuccessHandler;

    @Autowired
    private Clock clock;

    @Autowired
    private IamAccountService accountService;

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    @Autowired
    private CookieCsrfTokenRepository csrfTokenRepository;

    @Autowired
    public void configureGlobal(final AuthenticationManagerBuilder auth) throws Exception {
      auth.authenticationProvider(
          new IamLocalAuthenticationProvider(iamProperties, iamUserDetailsService, passwordEncoder,
              accountService, iamTotpMfaService, iamTotpMfaProperties));
    }

    @Override
    public void configure(final WebSecurity web) throws Exception {
      web.expressionHandler(oAuth2WebSecurityExpressionHandler);
    }


    public IamX509AuthenticationProvider iamX509AuthenticationProvider() {
      IamX509AuthenticationProvider provider = new IamX509AuthenticationProvider();
      provider.setPreAuthenticatedUserDetailsService(x509UserDetailsService);
      return provider;
    }

    public IamX509PreauthenticationProcessingFilter iamX509Filter() {
      return new IamX509PreauthenticationProcessingFilter(clock, x509CredentialExtractor,
          iamX509AuthenticationProvider(), successHandler(authenticationSuccessHandlerHelper()),
          certRepo, iamProperties);
    }

    protected AuthenticationEntryPoint entryPoint() {

      LoginUrlAuthenticationEntryPoint delegate = new LoginUrlAuthenticationEntryPoint("/login");
      return new HintAwareAuthenticationEntryPoint(delegate, hintService, aarcHintService);
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      http
        .requestMatchers(matchers -> matchers.antMatchers("/", "/login**", "/logout", "/authorize",
            "/manage/**", "/dashboard**", "/reset-session", "/device/**"))

        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
              .enableSessionUrlRewriting(false))

        .authorizeRequests(authorize -> authorize.antMatchers("/", "/login**")
          .permitAll()
          .antMatchers("/authorize")
          .permitAll()
          .antMatchers("/reset-session")
          .permitAll()
          .antMatchers("/device/**")
          .authenticated()
          .anyRequest()
          .authenticated())

        .formLogin(form -> form.loginPage("/login")
          .failureUrl("/login?error=failure")
          .successHandler(successHandler(authenticationSuccessHandlerHelper())))

        .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(entryPoint()))

        .addFilterBefore(authorizationRequestFilter, SecurityContextPersistenceFilter.class)

        // Replace the standard filter to use ExtendedAuthenticationToken.
        .addFilterAt(extendedAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)

        // Applied in the OAuth2 login flow.
        .addFilterAfter(extendedHttpServletRequestFilter(),
            UsernamePasswordAuthenticationFilter.class)

        .logout(
            logout -> logout.logoutUrl("/logout").logoutSuccessHandler(oidcLogoutSuccessHandler))

        .anonymous(Customizer.withDefaults())

        .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository))

        .addFilter(iamX509Filter());
    }

    @Bean
    OAuth2WebSecurityExpressionHandler oAuth2WebSecurityExpressionHandler() {
      return new OAuth2WebSecurityExpressionHandler();
    }

    @Bean
    SessionAuthenticationStrategy mfaSessionAuthenticationStrategy() {
      return new ChangeSessionIdAuthenticationStrategy();
    }

    @Bean
    AuthenticationSuccessHandlerHelper authenticationSuccessHandlerHelper() {
      return new AuthenticationSuccessHandlerHelper(clock, accountUtils, iamBaseUrl,
          aupSignatureCheckService, accountService, iamTotpMfaService, iamTotpMfaProperties,
          eventPublisher, mfaSessionAuthenticationStrategy());
    }

    public ExtendedAuthenticationFilter extendedAuthenticationFilter() throws Exception {
      return new ExtendedAuthenticationFilter(this.authenticationManager(),
          successHandler(authenticationSuccessHandlerHelper()), failureHandler());
    }

    public ExtendedHttpServletRequestFilter extendedHttpServletRequestFilter() {
      return new ExtendedHttpServletRequestFilter();
    }

    public AuthenticationSuccessHandler successHandler(AuthenticationSuccessHandlerHelper helper) {
      return new CheckMultiFactorIsEnabledSuccessHandler(helper);
    }

    public AuthenticationFailureHandler failureHandler() {
      return new SimpleUrlAuthenticationFailureHandler("/login?error=failure");
    }
  }

  @Configuration
  @Order(101)
  public static class RegistrationConfig extends WebSecurityConfigurerAdapter {

    public static final String START_REGISTRATION_ENDPOINT = "/start-registration";

    private final UserLoginConfig userLoginConfig;
    private final IamProperties iamProperties;
    private final CookieCsrfTokenRepository csrfTokenRepository;

    public RegistrationConfig(UserLoginConfig userLoginConfig, IamProperties iamProperties,
        CookieCsrfTokenRepository csrfTokenRepository) {

      this.userLoginConfig = userLoginConfig;
      this.iamProperties = iamProperties;
      this.csrfTokenRepository = csrfTokenRepository;
    }

    AccessDeniedHandler accessDeniedHandler() {
      return (request, response, authError) -> {
        RequestDispatcher dispatcher =
            request.getRequestDispatcher("/registration/insufficient-auth");
        request.setAttribute("authError", authError);
        dispatcher.forward(request, response);
      };
    }

    AuthenticationEntryPoint entryPoint() {
      String discoveryId;
      if (OIDC.equals(iamProperties.getRegistration().getAuthenticationType())) {
        discoveryId = String.format("/openid_connect_login?iss=%s",
            iamProperties.getRegistration().getOidcIssuer());
      } else {
        discoveryId =
            String.format("/saml/login?idp=%s", iamProperties.getRegistration().getSamlEntityId());
      }
      return new LoginUrlAuthenticationEntryPoint(discoveryId);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

      boolean certificateVisible = Optional.ofNullable(iamProperties.getRegistration())
        .map(IamProperties.RegistrationProperties::getFields)
        .map(fields -> fields.get(RegistrationField.CERTIFICATE))
        .map(IamProperties.RegistrationFieldProperties::getFieldBehaviour)
        .orElse(
            ExternalAuthAttributeSectionBehaviour.HIDDEN) != ExternalAuthAttributeSectionBehaviour.HIDDEN;

      http.antMatcher(START_REGISTRATION_ENDPOINT)

        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
              .enableSessionUrlRewriting(false))

        .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository));

      if (certificateVisible) {
        http.addFilter(userLoginConfig.iamX509Filter());
      }

      if (iamProperties.getRegistration().isRequireExternalAuthentication()) {

        http
          .authorizeRequests(authorize -> authorize.anyRequest()
            .hasAuthority(EXT_AUTHN_UNREGISTERED_USER_AUTH.getAuthority()))

          .exceptionHandling(exceptions -> exceptions.accessDeniedHandler(accessDeniedHandler())
            .authenticationEntryPoint(entryPoint()));

      } else {

        http.authorizeRequests(authorize -> authorize.anyRequest().permitAll());
      }
    }
  }

  @Configuration
  @Order(105)
  public static class ExternalOidcLogin extends WebSecurityConfigurerAdapter {

    @Value("${iam.baseUrl}")
    private String iamBaseUrl;

    @Autowired
    @Qualifier("OIDCAuthenticationManager")
    private AuthenticationManager oidcAuthManager;

    @Autowired
    OIDCAuthenticationProvider authProvider;

    @Autowired
    private IamProperties iamProperties;

    @Autowired
    private CookieCsrfTokenRepository csrfTokenRepository;

    private OIDCAuthenticationFilter oidcFilter;
    private UserLoginConfig userLoginConfig;

    public ExternalOidcLogin(
        @Qualifier("OIDCAuthenticationFilter") OIDCAuthenticationFilter oidcClientFilter,
        UserLoginConfig userLoginConfig) {
      this.oidcFilter = oidcClientFilter;
      this.userLoginConfig = userLoginConfig;
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {

      return oidcAuthManager;
    }

    public LoginUrlAuthenticationEntryPoint authenticationEntryPoint() {
      return new LoginUrlAuthenticationEntryPoint("/openid_connect_login");
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
      auth.authenticationProvider(authProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

      boolean certificateVisible = Optional.ofNullable(iamProperties.getRegistration())
        .map(IamProperties.RegistrationProperties::getFields)
        .map(fields -> fields.get(RegistrationField.CERTIFICATE))
        .map(IamProperties.RegistrationFieldProperties::getFieldBehaviour)
        .orElse(
            ExternalAuthAttributeSectionBehaviour.HIDDEN) != ExternalAuthAttributeSectionBehaviour.HIDDEN;

      http.antMatcher("/openid_connect_login**")

        .exceptionHandling(
            exceptions -> exceptions.authenticationEntryPoint(authenticationEntryPoint()))

        .addFilterAfter(oidcFilter, SecurityContextPersistenceFilter.class)

        .authorizeRequests(authorize -> authorize.anyRequest().permitAll())

        .sessionManagement(session -> session.enableSessionUrlRewriting(false)
          .sessionCreationPolicy(SessionCreationPolicy.ALWAYS))

        .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository));

      if (certificateVisible) {
        http.addFilter(userLoginConfig.iamX509Filter());
      }
    }
  }

  @Configuration
  @Order(Ordered.HIGHEST_PRECEDENCE)
  @Profile("h2-console")
  public static class H2ConsoleEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      http.requestMatchers(matchers -> matchers.antMatchers("/h2-console", "/h2-console/**"))

        .csrf(csrf -> csrf.disable())

        .httpBasic(Customizer.withDefaults())

        .headers(headers -> headers.frameOptions(FrameOptionsConfig::disable))

        .authorizeRequests(
            authorize -> authorize.antMatchers("/h2-console/**", "/h2-console").permitAll());
    }

    @Override
    public void configure(final WebSecurity builder) throws Exception {
      builder.debug(true);
    }
  }

  @Configuration
  @Order(102)
  public static class MultiFactorConfigurationAdapter extends WebSecurityConfigurerAdapter {

    @Autowired
    private CookieCsrfTokenRepository csrfTokenRepository;

    @Autowired
    @Qualifier("MultiFactorVerificationFilter")
    private MultiFactorVerificationFilter multiFactorVerificationFilter;

    public AuthenticationEntryPoint mfaAuthenticationEntryPoint() {
      return new LoginUrlAuthenticationEntryPoint("/login");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

      http.antMatcher(MFA_VERIFY_URL + "**")

        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
              .enableSessionUrlRewriting(false))

        .authorizeRequests(authorize -> authorize.anyRequest().hasRole("PRE_AUTHENTICATED"))

        .formLogin(form -> form.failureUrl(MFA_VERIFY_URL + "?error=failure"))

        .exceptionHandling(
            exceptions -> exceptions.authenticationEntryPoint(mfaAuthenticationEntryPoint()))

        .addFilterAt(multiFactorVerificationFilter, UsernamePasswordAuthenticationFilter.class)

        .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository));
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

    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    @Qualifier("clientUserDetailsService")
    private UserDetailsService userDetailsService;

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
