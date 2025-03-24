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
package it.infn.mw.iam.config.oidc;

import java.time.Clock;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.http.client.HttpClient;
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
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import com.google.common.collect.Sets;

import it.infn.mw.iam.authn.AuthenticationSuccessHandlerHelper;
import it.infn.mw.iam.authn.ExternalAuthenticationFailureHandler;
import it.infn.mw.iam.authn.ExternalAuthenticationSuccessHandler;
import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.common.config.AuthenticationValidator;
import it.infn.mw.iam.authn.oidc.DefaultOidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.DefaultRestTemplateFactory;
import it.infn.mw.iam.authn.oidc.OidcAuthenticationProvider;
import it.infn.mw.iam.authn.oidc.OidcClientFilter;
import it.infn.mw.iam.authn.oidc.OidcExceptionMessageHelper;
import it.infn.mw.iam.authn.oidc.OidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.service.DefaultOidcUserDetailsService;
import it.infn.mw.iam.authn.oidc.service.NullClientConfigurationService;
import it.infn.mw.iam.authn.oidc.service.OidcUserDetailsService;
import it.infn.mw.iam.authn.util.SessionTimeoutHelper;
import it.infn.mw.iam.core.IamThirdPartyIssuerService;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

@Configuration
public class OidcConfiguration {

  @Value("${iam.baseUrl}")
  private String iamBaseUrl;

  public static final String DEFINE_ME_PLEASE = "define_me_please";

  @Bean
  FilterRegistrationBean<OidcClientFilter> disabledAutomaticOidcFilterRegistration(
      OidcClientFilter f) {

    FilterRegistrationBean<OidcClientFilter> b = new FilterRegistrationBean<>(f);
    b.setEnabled(false);
    return b;
  }

  @Bean(name = "OIDCAuthenticationFilter")
  OidcClientFilter openIdConnectAuthenticationFilterCanl(OidcTokenRequestor tokenRequestor,
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
  @Profile("!canl")
  RestTemplateFactory restTemplateFactory() {

    return new DefaultRestTemplateFactory(new HttpComponentsClientHttpRequestFactory());
  }

  @Bean
  @Profile("canl")
  RestTemplateFactory canlRestTemplateFactory(
      @Qualifier("canlRequestFactory") ClientHttpRequestFactory rf) {

    return new DefaultRestTemplateFactory(rf);
  }

  @Bean(name = "OIDCExternalAuthenticationFailureHandler")
  AuthenticationFailureHandler failureHandler() {

    return new ExternalAuthenticationFailureHandler(new OidcExceptionMessageHelper());
  }

  @Bean(name = "OIDCExternalAuthenticationSuccessHandler")
  AuthenticationSuccessHandler successHandler(AuthenticationSuccessHandlerHelper helper) {

    return new ExternalAuthenticationSuccessHandler("/", helper);
  }

  @Bean(name = "OIDCAuthenticationManager")
  AuthenticationManager authenticationManager(
      OIDCAuthenticationProvider oidcAuthenticationProvider) {
    return new ProviderManager(Arrays.asList(oidcAuthenticationProvider));
  }

  @Bean
  OIDCAuthenticationProvider openIdConnectAuthenticationProvider(Clock clock,
      OidcUserDetailsService userDetailService, UserInfoFetcher userInfoFetcher,
      AuthenticationValidator<OIDCAuthenticationToken> validator,
      SessionTimeoutHelper timeoutHelper, IamAccountRepository accountRepo,
      IamTotpMfaRepository totpMfaRepository) {

    OidcAuthenticationProvider provider = new OidcAuthenticationProvider(userDetailService,
        validator, timeoutHelper, accountRepo, totpMfaRepository);

    provider.setUserInfoFetcher(userInfoFetcher);

    return provider;
  }

  @Bean
  IssuerService oidcIssuerService() {

    return new IamThirdPartyIssuerService();
  }

  @Bean
  @Profile("!canl")
  ServerConfigurationService dynamicServerConfiguration() {

    return new DynamicServerConfigurationService();
  }

  @Bean
  @Profile("canl")
  ServerConfigurationService canlDynamicServerConfiguration(
      @Qualifier("canlHttpClient") HttpClient client) {

    return new DynamicServerConfigurationService(client);
  }

  public boolean configuredProvider(OidcProvider provider) {
    return !Strings.isNullOrEmpty(provider.getClient().getClientId());
  }

  @Bean
  ClientConfigurationService oidcClientConfiguration(OidcValidatedProviders providers) {

    Map<String, RegisteredClient> clients = new LinkedHashMap<>();

    providers.getValidatedProviders().forEach(provider -> {
      RegisteredClient rc = new RegisteredClient();
      rc.setClientId(provider.getClient().getClientId());
      rc.setClientSecret(provider.getClient().getClientSecret());
      rc.setRedirectUris(
          Sets.newLinkedHashSet(Arrays.asList(provider.getClient().getRedirectUris())));
      rc.setScope(Sets.newLinkedHashSet(Arrays.asList(provider.getClient().getScope().split(","))));
      clients.put(provider.getIssuer(), rc);
    });

    if (clients.isEmpty()) {
      return new NullClientConfigurationService();
    }


    StaticClientConfigurationService config = new StaticClientConfigurationService();
    config.setClients(clients);

    return config;
  }

  @Bean
  AuthRequestOptionsService authOptions() {

    return new StaticAuthRequestOptionsService();
  }

  @Bean
  AuthRequestUrlBuilder authRequestBuilder() {

    return new PlainAuthRequestUrlBuilder();
  }

  @Bean
  OidcUserDetailsService userDetailService(IamAccountRepository repo,
      InactiveAccountAuthenticationHander handler) {

    return new DefaultOidcUserDetailsService(repo, handler);
  }

  @Bean
  UserInfoFetcher userInfoFetcher() {
    return new UserInfoFetcher();
  }

  @Bean
  OidcTokenRequestor tokenRequestor(RestTemplateFactory restTemplateFactory, ObjectMapper mapper) {
    return new DefaultOidcTokenRequestor(restTemplateFactory, mapper);
  }
}
