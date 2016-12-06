package it.infn.mw.iam.config;

import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.oauth2.web.CorsFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import it.infn.mw.iam.authn.RootIsDashboardSuccessHandler;
import it.infn.mw.iam.authn.TimestamperSuccessHandler;
import it.infn.mw.iam.authn.oidc.OidcAccessDeniedHandler;
import it.infn.mw.iam.authn.oidc.OidcAuthenticationProvider;
import it.infn.mw.iam.authn.oidc.OidcClientFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {



  @Configuration
  @Order(100)
  public static class UserLoginConfig extends WebSecurityConfigurerAdapter {

    @Value("${iam.baseUrl}")
    private String iamBaseUrl;

    @Autowired
    private OAuth2WebSecurityExpressionHandler oAuth2WebSecurityExpressionHandler;

    @Autowired
    @Qualifier("mitreAuthzRequestFilter")
    private GenericFilterBean authorizationRequestFilter;

    @Autowired
    @Qualifier("iamUserDetailsService")
    private UserDetailsService iamUserDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    public void configureGlobal(final AuthenticationManagerBuilder auth) throws Exception {
      // @formatter:off
      auth
        .userDetailsService(iamUserDetailsService)
        .passwordEncoder(passwordEncoder);
      // @formatter:on
    }

    @Override
    public void configure(final WebSecurity web) throws Exception {

      web.expressionHandler(oAuth2WebSecurityExpressionHandler);
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      // @formatter:off

      http.requestMatchers()
        .antMatchers("/", "/login**", "/logout", "/authorize", "/manage/**", "/dashboard**", "/register",
            "/reset-session")
        .and()
        .sessionManagement()
          .enableSessionUrlRewriting(false)
        .and()
          .authorizeRequests()
            .antMatchers("/login**", "/webjars/**").permitAll()
            .antMatchers("/register").permitAll()
            .antMatchers("/authorize**").permitAll()
            .antMatchers("/reset-session").permitAll()
            .antMatchers("/").authenticated()
        .and()
          .formLogin()
            .loginPage("/login")
            .failureUrl("/login?error=failure")
            .successHandler(successHandler())
        .and()
          .exceptionHandling()
            .accessDeniedHandler(new OidcAccessDeniedHandler())
        .and()
          .addFilterBefore(authorizationRequestFilter, SecurityContextPersistenceFilter.class)
        .logout()
          .logoutUrl("/logout")
        .and().anonymous()
        .and()
          .csrf()
            .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/authorize")).disable();
      // @formatter:on
    }

    @Bean
    public OAuth2WebSecurityExpressionHandler oAuth2WebSecurityExpressionHandler() {

      return new OAuth2WebSecurityExpressionHandler();
    }

    public AuthenticationSuccessHandler successHandler() {

      return new TimestamperSuccessHandler(new RootIsDashboardSuccessHandler(iamBaseUrl));
    }
  }

  @Configuration
  @Order(105)
  @Profile("google")
  public static class ExternalOidcLogin extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("OIDCAuthenticationManager")
    private AuthenticationManager oidcAuthManager;

    @Autowired
    OidcAuthenticationProvider authProvider;

    @Autowired
    @Qualifier("OIDCAuthenticationFilter")
    private OidcClientFilter oidcFilter;

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {

      return oidcAuthManager;
    }

    // @Bean(name = "ExternalAuthenticationEntryPoint")
    public LoginUrlAuthenticationEntryPoint authenticationEntryPoint() {

      return new LoginUrlAuthenticationEntryPoint("/openid_connect_login");
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {

      auth.authenticationProvider(authProvider);
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      // @formatter:off
      http
	.antMatcher("/openid_connect_login**")
	.exceptionHandling()
          .authenticationEntryPoint(authenticationEntryPoint())
	  .accessDeniedHandler(new OidcAccessDeniedHandler())
	.and()
          .addFilterAfter(oidcFilter, SecurityContextPersistenceFilter.class).authorizeRequests()
	  .antMatchers("/openid_connect_login**")
	    .permitAll()
	.and()
	  .sessionManagement()
	    .enableSessionUrlRewriting(false)
	    .sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
      // @formatter:on
    }
  }

  @Configuration
  @Order(9)
  public static class OAuthResourceServerConfiguration {

    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private OAuth2TokenEntityService tokenService;

    @Bean
    public FilterRegistrationBean disabledAutomaticFilterRegistration(
        final OAuth2AuthenticationProcessingFilter f) {

      FilterRegistrationBean b = new FilterRegistrationBean(f);
      b.setEnabled(false);
      return b;
    }

    @Bean(name = "resourceServerFilter")
    public OAuth2AuthenticationProcessingFilter oauthResourceServerFilter() {

      OAuth2AuthenticationManager manager = new OAuth2AuthenticationManager();
      manager.setTokenServices(tokenService);

      OAuth2AuthenticationProcessingFilter filter = new OAuth2AuthenticationProcessingFilter();
      filter.setAuthenticationEntryPoint(authenticationEntryPoint);
      filter.setAuthenticationManager(manager);
      filter.setStateless(false);
      return filter;
    }

  }

  @Configuration
  @Order(10)
  public static class ApiEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("resourceServerFilter")
    private OAuth2AuthenticationProcessingFilter resourceFilter;

    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private CorsFilter corsFilter;

    @Override
    public void configure(final HttpSecurity http) throws Exception {

      // @formatter:off
      http.antMatcher("/api/**")
          .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)
          .addFilterBefore(corsFilter, WebAsyncManagerIntegrationFilter.class).exceptionHandling()
          .authenticationEntryPoint(authenticationEntryPoint).and().sessionManagement()
          .sessionCreationPolicy(SessionCreationPolicy.NEVER).and().csrf().disable();
      // @formatter:on

    }
  }

  /**
   * @author cecco
   *
   */
  @Configuration
  @Order(11)
  public static class ResourceEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2AuthenticationProcessingFilter resourceFilter;

    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private CorsFilter corsFilter;

    @Override

    public void configure(final HttpSecurity http) throws Exception {

      // @formatter:off
      http.antMatcher("/resource/**").exceptionHandling()
          .authenticationEntryPoint(authenticationEntryPoint).and()
          .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)
          .addFilterBefore(corsFilter, WebAsyncManagerIntegrationFilter.class).sessionManagement()
          .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().authorizeRequests()
          .antMatchers("/resource/**").permitAll().and().csrf().disable();
      // @formatter:on
    }
  }

  /**
   * @author cecco
   *
   */
  @Configuration
  @Order(12)
  public static class RegisterEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2AuthenticationProcessingFilter resourceFilter;

    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private CorsFilter corsFilter;

    @Override
    public void configure(final HttpSecurity http) throws Exception {

      // @formatter:off
      http.antMatcher("/register/**").exceptionHandling()
          .authenticationEntryPoint(authenticationEntryPoint).and()
          .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)
          .addFilterBefore(corsFilter, WebAsyncManagerIntegrationFilter.class).sessionManagement()
          .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().authorizeRequests()
          .antMatchers("/register/**").permitAll().and().csrf().disable();
      // @formatter:on
    }
  }

  /**
   * @author cecco
   *
   */
  @Configuration
  @Order(13)
  public static class UserInfoEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2AuthenticationProcessingFilter resourceFilter;

    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private CorsFilter corsFilter;

    @Override

    public void configure(final HttpSecurity http) throws Exception {

      // @formatter:off
      http.antMatcher("/userinfo**").exceptionHandling()
          .authenticationEntryPoint(authenticationEntryPoint).and()
          .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)
          .addFilterBefore(corsFilter, WebAsyncManagerIntegrationFilter.class).sessionManagement()
          .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().csrf().disable();
      // @formatter:on
    }
  }

  @Configuration
  @Order(15)
  public static class IntrospectEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    @Qualifier("clientUserDetailsService")
    private UserDetailsService userDetailsService;

    @Autowired
    private CorsFilter corsFilter;

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {

      auth.userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      // @formatter:off
      http.antMatcher("/introspect/**")
        .httpBasic()
          .authenticationEntryPoint(authenticationEntryPoint)
        .and()
          .addFilterBefore(corsFilter, SecurityContextPersistenceFilter.class)
            .exceptionHandling()
          .authenticationEntryPoint(authenticationEntryPoint)
        .and()
          .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
        .csrf()
          .disable()
        .authorizeRequests()
          .anyRequest()
            .fullyAuthenticated();
      // @formatter:on
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

    @Autowired
    private CorsFilter corsFilter;

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {

      auth.userDetailsService(userDetailsService);
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

      // @formatter:off
      http.antMatcher("/revoke**").httpBasic().authenticationEntryPoint(authenticationEntryPoint)
          .and().addFilterBefore(corsFilter, SecurityContextPersistenceFilter.class)
          .addFilterBefore(clientCredentialsEndpointFilter(), BasicAuthenticationFilter.class)
          .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint).and()
          .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
      // @formatter:on
    }
  }

  @Configuration
  @Order(17)
  public static class JwkEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private Http403ForbiddenEntryPoint http403ForbiddenEntryPoint;

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      // @formatter:off
      http.antMatcher("/jwk**").exceptionHandling()
          .authenticationEntryPoint(http403ForbiddenEntryPoint).and().sessionManagement()
          .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().authorizeRequests()
          .antMatchers("/**").permitAll();
      // @formatter:on
    }
  }

  @Configuration
  @Order(18)
  public static class ScimApiEndpointConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2AuthenticationProcessingFilter resourceFilter;

    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private CorsFilter corsFilter;

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      http.antMatcher("/scim/**")
        .exceptionHandling()
        .authenticationEntryPoint(authenticationEntryPoint)
        .and()
        .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)
        .addFilterBefore(corsFilter, WebAsyncManagerIntegrationFilter.class)
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.NEVER)
        .and()
        .authorizeRequests()
        .antMatchers("/scim/**")
        .authenticated()
        .and()
        .csrf()
        .disable();
    }
  }

  @Configuration
  @Order(19)
  public static class RegistrationEndpointConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2AuthenticationProcessingFilter resourceFilter;

    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private CorsFilter corsFilter;

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      // @formatter:off
      http
        .antMatcher("/registration/**")
          .exceptionHandling()
            .authenticationEntryPoint(authenticationEntryPoint)
          .and()
            .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)
            .addFilterBefore(corsFilter, WebAsyncManagerIntegrationFilter.class)
            .sessionManagement()
              .sessionCreationPolicy(SessionCreationPolicy.NEVER)
          .and()
            .authorizeRequests()
              .antMatchers(HttpMethod.POST, "/registration/create").permitAll()
              .antMatchers(HttpMethod.GET, "/registration/username-available/**").permitAll()
              .antMatchers(HttpMethod.GET, "/registration/email-available/**").permitAll()
              .antMatchers(HttpMethod.GET, "/registration/confirm/**").permitAll()
              .antMatchers(HttpMethod.GET, "/registration/verify/**").permitAll()
              .antMatchers(HttpMethod.GET, "/registration/submitted").permitAll()
              .antMatchers("/registration/**").authenticated()
          .and()
            .csrf()
              .disable();
      // @formatter:on
    }
  }

  @Configuration
  @Order(20)
  public static class AuthnInfoEndpointConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http.antMatcher("/iam/authn-info/**")
        .exceptionHandling()
        .authenticationEntryPoint(authenticationEntryPoint)
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.NEVER)
        .and()
        .authorizeRequests()
        .antMatchers("/iam/authn-info/**")
        .authenticated();
    }

  }

  @Configuration
  @Order(21)
  public static class AccountLinkingEndpointConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http.antMatcher("/iam/account-linking/**")
        .exceptionHandling()
        .authenticationEntryPoint(authenticationEntryPoint)
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.NEVER)
        .and()
        .csrf()
        .disable()
        .authorizeRequests()
        .antMatchers("/iam/account-linking/**")
        .authenticated();
    }
  }

  @Configuration
  @Order(22)
  public static class AccountAuthorityEndpointConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http.requestMatchers()
        .antMatchers("/iam/account/**", "/iam/me/**")
        .and()
        .exceptionHandling()
        .authenticationEntryPoint(authenticationEntryPoint)
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.NEVER)
        .and()
        .authorizeRequests()
        .antMatchers("/iam/account/**", "/iam/me/**")
        .authenticated()
        .and()
        .csrf()
        .disable();
    }
  }

  @Configuration
  @Order(23)
  public static class PasswordUpdateApiEndpointConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2AuthenticationProcessingFilter resourceFilter;

    @Autowired
    private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private CorsFilter corsFilter;

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      http.antMatcher("/iam/password-update")
        .exceptionHandling()
        .authenticationEntryPoint(authenticationEntryPoint)
        .and()
        .addFilterAfter(resourceFilter, SecurityContextPersistenceFilter.class)
        .addFilterBefore(corsFilter, WebAsyncManagerIntegrationFilter.class)
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.NEVER)
        .and()
        .authorizeRequests()
        .antMatchers("/iam/password-update")
        .authenticated()
        .and()
        .csrf()
        .disable();
    }
  }

  @Configuration
  @Order(Ordered.HIGHEST_PRECEDENCE)
  @Profile("dev")
  public static class H2ConsoleEndpointAuthorizationConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

      HttpSecurity h2Console = http.requestMatchers()
        .antMatchers("/h2-console", "/h2-console/**")
        .and()
        .csrf()
        .disable();

      h2Console.httpBasic();
      h2Console.headers().frameOptions().disable();

      h2Console.authorizeRequests().antMatchers("/h2-console/**", "/h2-console").permitAll();
    }

    @Override
    public void configure(final WebSecurity builder) throws Exception {

      builder.debug(true);
    }
  }

}
