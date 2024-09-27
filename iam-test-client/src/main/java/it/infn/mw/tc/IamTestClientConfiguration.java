package it.infn.mw.tc;

import static java.util.stream.Collectors.toSet;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.client.HttpClient;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.logging.log4j.util.Strings;
import org.italiangrid.voms.util.CertificateValidatorBuilder;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.OIDCAuthenticationFilter;
import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.client.service.AuthRequestOptionsService;
import org.mitre.openid.connect.client.service.IssuerService;
import org.mitre.openid.connect.client.service.impl.StaticClientConfigurationService;
import org.mitre.openid.connect.client.service.impl.StaticSingleIssuerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.impl.SocketFactoryCreator;

@SuppressWarnings("deprecation")
@Configuration
public class IamTestClientConfiguration {

  @Autowired
  private IamClientApplicationProperties iamClientConfig;

  @Bean
  SecurityFilterChain filterChain(HttpSecurity http, OIDCAuthenticationFilter oidcFilter)
      throws Exception {

    http
      .authorizeHttpRequests(requests -> requests
        .antMatchers("/", "/user", "/error", "/openid_connect_login**", "/webjars/**")
        .permitAll()
        .antMatchers("/**")
        .authenticated())
      .exceptionHandling(handling -> handling
        .authenticationEntryPoint(new SendUnauhtorizedAuthenticationEntryPoint()))
      .logout(logout -> logout.logoutSuccessUrl("/").permitAll())
      .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository()))
      .addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
      .addFilterAfter(oidcFilter, SecurityContextPersistenceFilter.class)
      .sessionManagement(management -> management.enableSessionUrlRewriting(false)
        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS));

    return http.build();
  }

  private CsrfTokenRepository csrfTokenRepository() {

    HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
    repository.setHeaderName("X-XSRF-TOKEN");
    return repository;
  }

  private Filter csrfHeaderFilter() {

    return new OncePerRequestFilter() {

      @Override
      protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
          FilterChain filterChain) throws ServletException, IOException {

        CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrf != null) {
          Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
          String token = csrf.getToken();
          if (cookie == null || token != null && !token.equals(cookie.getValue())) {
            cookie = new Cookie("XSRF-TOKEN", token);
            cookie.setPath("/");
            response.addCookie(cookie);
          }
        }
        filterChain.doFilter(request, response);
      }
    };
  }

  @Bean
  FilterRegistrationBean<OIDCAuthenticationFilter> disabledAutomaticOidcFilterRegistration(
      OIDCAuthenticationFilter f) {
    FilterRegistrationBean<OIDCAuthenticationFilter> b =
        new FilterRegistrationBean<OIDCAuthenticationFilter>(f);
    b.setEnabled(false);
    return b;
  }

  @Bean(name = "openIdConnectAuthenticationFilter")
  OIDCAuthenticationFilter openIdConnectAuthenticationFilter()
      throws NoSuchAlgorithmException, KeyStoreException {

    ClientHttpRequestFactory rf = httpRequestFactory();
    IamOIDCClientFilter filter = new IamOIDCClientFilter();

    filter.setAuthenticationManager(authenticationManager());
    filter.setIssuerService(iamIssuerService());

    filter.setServerConfigurationService(new IamDynamicServerConfigurationService(rf));
    filter.setValidationServices(new IamJWKCacheSetService(rf));

    filter.setClientConfigurationService(staticClientConfiguration());
    filter.setAuthRequestOptionsService(authOptions());
    filter.setAuthRequestUrlBuilder(new IamAuthRequestUrlBuilder());
    filter.setHttpRequestFactory(httpRequestFactory());



    filter.setAuthenticationFailureHandler(new SaveAuhenticationError());


    return filter;
  }

  @Bean(name = "OIDCAuthenticationManager")
  AuthenticationManager authenticationManager() throws NoSuchAlgorithmException, KeyStoreException {

    return new ProviderManager(Arrays.asList(openIdConnectAuthenticationProvider()));
  }

  @Bean
  OIDCAuthenticationProvider openIdConnectAuthenticationProvider() throws NoSuchAlgorithmException {

    OIDCAuthenticationProvider provider = new OIDCAuthenticationProvider();
    provider.setUserInfoFetcher(new IamUserInfoFetcher(httpRequestFactory()));

    return provider;
  }

  private IssuerService iamIssuerService() {

    StaticSingleIssuerService issuerService = new StaticSingleIssuerService();
    issuerService.setIssuer(iamClientConfig.getIssuer());

    return issuerService;
  }

  private StaticClientConfigurationService staticClientConfiguration() {

    Map<String, RegisteredClient> clients = new LinkedHashMap<>();

    ClientDetailsEntity cde = new ClientDetailsEntity();
    cde.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
    cde.setClientId(iamClientConfig.getClient().getClientId());
    cde.setClientSecret(iamClientConfig.getClient().getClientSecret());
    cde.setCodeChallengeMethod(iamClientConfig.getClient().getCodeChallengeMethod());

    if (Strings.isNotBlank(iamClientConfig.getClient().getScope())) {
      cde.setScope(Stream.of(iamClientConfig.getClient().getScope().split(" ")).collect(toSet()));
    }

    clients.put(iamClientConfig.getIssuer(), new RegisteredClient(cde));

    StaticClientConfigurationService config = new StaticClientConfigurationService();
    config.setClients(clients);

    return config;
  }

  private AuthRequestOptionsService authOptions() {

    return new IamAuthRequestOptionsService(iamClientConfig);
  }

  public X509CertChainValidatorExt certificateValidator() {
    NamespaceCheckingMode namespaceChecks = CertificateValidatorBuilder.DEFAULT_NS_CHECKS;

    if (iamClientConfig.getTls().isIgnoreNamespaceChecks()) {
      namespaceChecks = NamespaceCheckingMode.IGNORE;
    }

    return new CertificateValidatorBuilder().lazyAnchorsLoading(false)
      .namespaceChecks(namespaceChecks)
      .trustAnchorsUpdateInterval(TimeUnit.HOURS.toMillis(1))
      .build();
  }


  public SSLContext sslContext() throws NoSuchAlgorithmException {

    SecureRandom r = new SecureRandom();

    try {
      SSLContext context = SSLContext.getInstance(iamClientConfig.getTls().getVersion());

      X509TrustManager tm = SocketFactoryCreator.getSSLTrustManager(certificateValidator());
      context.init(null, new TrustManager[] {tm}, r);

      return context;

    } catch (NoSuchAlgorithmException | KeyManagementException e) {
      throw new RuntimeException(e);
    }

  }

  public HttpClient httpClient() throws NoSuchAlgorithmException {

    SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(sslContext());

    Registry<ConnectionSocketFactory> socketFactoryRegistry =
        RegistryBuilder.<ConnectionSocketFactory>create()
          .register("https", sf)
          .register("http", PlainConnectionSocketFactory.getSocketFactory())
          .build();

    PoolingHttpClientConnectionManager connectionManager =
        new PoolingHttpClientConnectionManager(socketFactoryRegistry);
    connectionManager.setMaxTotal(10);
    connectionManager.setDefaultMaxPerRoute(10);

    return HttpClientBuilder.create()
      .setConnectionManager(connectionManager)
      .disableAuthCaching()
      .build();
  }

  @Bean
  ClientHttpRequestFactory httpRequestFactory() throws NoSuchAlgorithmException {

    if (iamClientConfig.getTls().isUseGridTrustAnchors()) {
      return new HttpComponentsClientHttpRequestFactory(httpClient());
    } else {
      return new HttpComponentsClientHttpRequestFactory();
    }

  }



}
