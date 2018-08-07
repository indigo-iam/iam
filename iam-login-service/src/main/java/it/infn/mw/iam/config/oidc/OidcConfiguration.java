/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2018
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.AUPSignatureCheckService;
import it.infn.mw.iam.authn.EnforceAupSignatureSuccessHandler;
import it.infn.mw.iam.authn.ExternalAuthenticationFailureHandler;
import it.infn.mw.iam.authn.ExternalAuthenticationSuccessHandler;
import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.RootIsDashboardSuccessHandler;
import it.infn.mw.iam.authn.oidc.DefaultOidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.DefaultRestTemplateFactory;
import it.infn.mw.iam.authn.oidc.OidcAuthenticationProvider;
import it.infn.mw.iam.authn.oidc.OidcClientFilter;
import it.infn.mw.iam.authn.oidc.OidcExceptionMessageHelper;
import it.infn.mw.iam.authn.oidc.OidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.service.DefaultOidcUserDetailsService;
import it.infn.mw.iam.authn.oidc.service.OidcUserDetailsService;
import it.infn.mw.iam.core.IamThirdPartyIssuerService;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Configuration
public class OidcConfiguration {

  @Value("${iam.baseUrl}")
  private String iamBaseUrl;

  @Autowired
  private OidcProviderProperties oidcConfig;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private AUPSignatureCheckService aupSignatureCheckService;

  @Autowired
  private AccountUtils accountUtils;

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

    EnforceAupSignatureSuccessHandler successHandler = new EnforceAupSignatureSuccessHandler(sa,
        aupSignatureCheckService, accountUtils, accountRepo);

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
  public IssuerService oidcIssuerService() {

    return new IamThirdPartyIssuerService();
  }

  @Bean
  public ServerConfigurationService dynamicServerConfiguration() {

    return new DynamicServerConfigurationService();
  }

  @Bean
  public ClientConfigurationService staticClientConfiguration() {

    Map<String, RegisteredClient> clients = new LinkedHashMap<>();

    for (OidcProvider provider : oidcConfig.getProviders()) {
      RegisteredClient rc = new RegisteredClient();
      rc.setClientId(provider.getClient().getClientId());
      rc.setClientSecret(provider.getClient().getClientSecret());
      rc.setRedirectUris(
          Sets.newLinkedHashSet(Arrays.asList(provider.getClient().getRedirectUris())));
      rc.setScope(Sets.newLinkedHashSet(Arrays.asList(provider.getClient().getScope().split(","))));
      clients.put(provider.getIssuer(), rc);
    }

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
