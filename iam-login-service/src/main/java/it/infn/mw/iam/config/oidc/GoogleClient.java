package it.infn.mw.iam.config.oidc;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.client.UserInfoFetcher;
import org.mitre.openid.connect.client.service.AuthRequestOptionsService;
import org.mitre.openid.connect.client.service.AuthRequestUrlBuilder;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitre.openid.connect.client.service.IssuerService;
import org.mitre.openid.connect.client.service.ServerConfigurationService;
import org.mitre.openid.connect.client.service.impl.DynamicServerConfigurationService;
import org.mitre.openid.connect.client.service.impl.PlainAuthRequestUrlBuilder;
import org.mitre.openid.connect.client.service.impl.StaticAuthRequestOptionsService;
import org.mitre.openid.connect.client.service.impl.StaticClientConfigurationService;
import org.mitre.openid.connect.client.service.impl.StaticSingleIssuerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.authn.ExternalAuthenticationFailureHandler;
import it.infn.mw.iam.authn.ExternalAuthenticationSuccessHandler;
import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.RootIsDashboardSuccessHandler;
import it.infn.mw.iam.authn.TimestamperSuccessHandler;
import it.infn.mw.iam.authn.oidc.DefaultOidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.DefaultRestTemplateFactory;
import it.infn.mw.iam.authn.oidc.OidcAuthenticationProvider;
import it.infn.mw.iam.authn.oidc.OidcClientFilter;
import it.infn.mw.iam.authn.oidc.OidcExceptionMessageHelper;
import it.infn.mw.iam.authn.oidc.OidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.service.DefaultOidcUserDetailsService;
import it.infn.mw.iam.authn.oidc.service.OidcUserDetailsService;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Configuration
@Profile("google")
public class GoogleClient {

  @Value("${iam.baseUrl}")
  private String iamBaseUrl;

  @Autowired
  private GoogleClientProperties googleClientProperties;

  @Bean
  public FilterRegistrationBean disabledAutomaticOidcFilterRegistration(OidcClientFilter f) {

    FilterRegistrationBean b = new FilterRegistrationBean(f);
    b.setEnabled(false);
    return b;
  }

  @Bean(name = "OIDCAuthenticationFilter")
  public OidcClientFilter openIdConnectAuthenticationFilterCanl(OidcTokenRequestor tokenRequestor,
      @Qualifier("OIDCAuthenticationManager") AuthenticationManager oidcAuthenticationManager,
      @Qualifier("OIDCExternalAuthenticationSuccessHandler") AuthenticationSuccessHandler successHandler,
      @Qualifier("OIDCExternalAuthenticationFailureHandler") AuthenticationFailureHandler failureHandler,
      IssuerService issuerService, ServerConfigurationService serverConfigurationService,
      ClientConfigurationService clientConfigurationService,
      AuthRequestUrlBuilder authRequestUrlBuilder,
      AuthRequestOptionsService authRequestOptionsService, JWKSetCacheService validationServices) {

    OidcClientFilter filter = new OidcClientFilter();
    filter.setAuthenticationManager(oidcAuthenticationManager);
    filter.setIssuerService(issuerService);
    filter.setServerConfigurationService(serverConfigurationService);
    filter.setClientConfigurationService(clientConfigurationService);
    filter.setAuthRequestOptionsService(authRequestOptionsService);
    filter.setAuthRequestUrlBuilder(authRequestUrlBuilder);
    filter.setAuthenticationSuccessHandler(successHandler);
    filter.setAuthenticationFailureHandler(failureHandler);
    filter.setValidationServices(validationServices);
    filter.setTokenRequestor(tokenRequestor);

    return filter;
  }

  @Bean
  public RestTemplateFactory restTemplateFactory() {

    return new DefaultRestTemplateFactory(new HttpComponentsClientHttpRequestFactory());

  }

  @Bean(name = "OIDCExternalAuthenticationFailureHandler")
  public AuthenticationFailureHandler failureHandler() {

    return new ExternalAuthenticationFailureHandler(new OidcExceptionMessageHelper());
  }

  @Bean(name = "OIDCExternalAuthenticationSuccessHandler")
  public AuthenticationSuccessHandler successHandler() {

    RootIsDashboardSuccessHandler sa =
        new RootIsDashboardSuccessHandler(iamBaseUrl, new HttpSessionRequestCache());
    AuthenticationSuccessHandler successHandler = new TimestamperSuccessHandler(sa);

    return new ExternalAuthenticationSuccessHandler(successHandler, "/");

  }

  @Bean(name = "OIDCAuthenticationManager")
  public AuthenticationManager authenticationManager(
      OIDCAuthenticationProvider oidcAuthenticationProvider) {
    return new ProviderManager(Arrays.asList(oidcAuthenticationProvider));
  }

  @Bean
  public OIDCAuthenticationProvider openIdConnectAuthenticationProvider(
      OidcUserDetailsService userDetailService, UserInfoFetcher userInfoFetcher) {

    OidcAuthenticationProvider provider = new OidcAuthenticationProvider(userDetailService);
    provider.setUserInfoFetcher(userInfoFetcher);

    return provider;
  }

  @Bean
  public IssuerService googleIssuerService() {

    StaticSingleIssuerService issuerService = new StaticSingleIssuerService();
    issuerService.setIssuer(googleClientProperties.getIssuer());

    return issuerService;
  }

  @Bean
  public ServerConfigurationService dynamicServerConfiguration() {

    return new DynamicServerConfigurationService();
  }

  @Bean
  public ClientConfigurationService staticClientConfiguration() {

    Map<String, RegisteredClient> clients = new LinkedHashMap<String, RegisteredClient>();

    clients.put(googleClientProperties.getIssuer(), googleClientProperties);

    StaticClientConfigurationService config = new StaticClientConfigurationService();
    config.setClients(clients);

    return config;
  }

  @Bean
  public AuthRequestOptionsService authOptions() {

    return new StaticAuthRequestOptionsService();
  }

  @Bean
  public AuthRequestUrlBuilder authRequestBuilder() {

    return new PlainAuthRequestUrlBuilder();
  }

  @Bean
  public OidcUserDetailsService userDetailService(IamAccountRepository repo,
      InactiveAccountAuthenticationHander handler) {

    return new DefaultOidcUserDetailsService(repo, handler);
  }

  @Bean
  public UserInfoFetcher userInfoFetcher() {
    return new UserInfoFetcher();
  }

  @Bean
  public OidcTokenRequestor tokenRequestor(RestTemplateFactory restTemplateFactory,
      ObjectMapper mapper) {
    return new DefaultOidcTokenRequestor(restTemplateFactory, mapper);
  }
}
