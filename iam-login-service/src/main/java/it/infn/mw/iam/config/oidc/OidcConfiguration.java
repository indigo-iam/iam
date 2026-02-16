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

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.google.common.base.Strings;
import com.google.common.collect.Sets;

import it.infn.mw.iam.authn.AuthenticationSuccessHandlerHelper;
import it.infn.mw.iam.authn.ExternalAuthenticationFailureHandler;
import it.infn.mw.iam.authn.ExternalAuthenticationSuccessHandler;
import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.common.config.AuthenticationValidator;
import it.infn.mw.iam.authn.oidc.AuthRequestUrlBuilder;
import it.infn.mw.iam.authn.oidc.DefaultOidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.OidcAuthenticationProvider;
import it.infn.mw.iam.authn.oidc.OidcClientFilter;
import it.infn.mw.iam.authn.oidc.OidcExceptionMessageHelper;
import it.infn.mw.iam.authn.oidc.OidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.PlainAuthRequestUrlBuilder;
import it.infn.mw.iam.authn.oidc.RegisteredClient;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.configuration.ClientConfigurationService;
import it.infn.mw.iam.authn.oidc.configuration.NullClientConfigurationService;
import it.infn.mw.iam.authn.oidc.configuration.ServerConfigurationService;
import it.infn.mw.iam.authn.oidc.configuration.StaticClientConfigurationService;
import it.infn.mw.iam.authn.oidc.mapper.OidcAuthoritiesMapper;
import it.infn.mw.iam.authn.oidc.model.OIDCAuthenticationToken;
import it.infn.mw.iam.authn.oidc.provisioning.OidcAccountProvisioningService;
import it.infn.mw.iam.authn.oidc.userinfo.UserInfoFetcher;
import it.infn.mw.iam.authn.util.SessionTimeoutHelper;
import it.infn.mw.iam.core.jwt.JwkSetCacheService;
import it.infn.mw.iam.core.jwt.SymmetricKeyJWTValidatorCacheService;
import it.infn.mw.iam.core.oidc.service.IamThirdPartyIssuerService;
import it.infn.mw.iam.core.oidc.service.IssuerService;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

@Configuration
@Profile("oidc")
@EnableConfigurationProperties(IamOidcJITAccountProvisioningProperties.class)
public class OidcConfiguration {

  @Value("${iam.baseUrl}")
  private String iamBaseUrl;

  public static final String DEFINE_ME_PLEASE = "define_me_please";

  @Bean
  OidcClientFilter openIdConnectAuthenticationFilterCanl(OidcTokenRequestor tokenRequestor,
      @Qualifier("OIDCAuthenticationManager") AuthenticationManager oidcAuthenticationManager,
      AuthenticationSuccessHandler successHandler, AuthenticationFailureHandler failureHandler,
      ServerConfigurationService serverConfigService,
      ClientConfigurationService clientConfigService,
      SymmetricKeyJWTValidatorCacheService symmetricKeyJwtValidatorCacheService,
      JwkSetCacheService validationServices, IssuerService issuerService,
      AuthRequestUrlBuilder authRequestUrlBuilder, Environment env) {

    return new OidcClientFilter(oidcAuthenticationManager, serverConfigService, clientConfigService,
        symmetricKeyJwtValidatorCacheService, validationServices, tokenRequestor, issuerService,
        authRequestUrlBuilder, env);
  }

  @Bean
  FilterRegistrationBean<OidcClientFilter> disabledAutomaticOidcFilterRegistration(
      OidcClientFilter f) {

    FilterRegistrationBean<OidcClientFilter> b = new FilterRegistrationBean<>(f);
    b.setEnabled(false);
    return b;
  }

  @Bean
  AuthenticationFailureHandler failureHandler() {

    return new ExternalAuthenticationFailureHandler(new OidcExceptionMessageHelper());
  }

  @Bean
  AuthenticationSuccessHandler successHandler(AuthenticationSuccessHandlerHelper helper) {

    return new ExternalAuthenticationSuccessHandler("/", helper);
  }

  @Bean(name = "OIDCAuthenticationManager")
  AuthenticationManager authenticationManager(
      OidcAuthenticationProvider oidcAuthenticationProvider) {
    return new ProviderManager(Arrays.asList(oidcAuthenticationProvider));
  }

  @Bean
  OidcAuthenticationProvider openIdConnectAuthenticationProvider(
      AuthenticationValidator<OIDCAuthenticationToken> authnValidator,
      SessionTimeoutHelper sessionTimeoutHelper, IamAccountRepository accountRepo,
      InactiveAccountAuthenticationHander inactiveAccountHandler,
      IamTotpMfaRepository totpMfaRepository, IamOidcJITAccountProvisioningProperties jitProperties,
      OidcAccountProvisioningService oidcProvisioningService, UserInfoFetcher userInfoFetcher,
      OidcAuthoritiesMapper authoritiesMapper) {

    return new OidcAuthenticationProvider(authnValidator, sessionTimeoutHelper, accountRepo,
        inactiveAccountHandler, totpMfaRepository, jitProperties, oidcProvisioningService,
        userInfoFetcher, authoritiesMapper);
  }

  @Bean
  IssuerService oidcIssuerService() {

    return new IamThirdPartyIssuerService();
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

    return new StaticClientConfigurationService(clients);
  }

  @Bean
  AuthRequestUrlBuilder authRequestBuilder() {

    return new PlainAuthRequestUrlBuilder();
  }

  @Bean
  UserInfoFetcher userInfoFetcher() {

    return new UserInfoFetcher(HttpClientBuilder.create().useSystemProperties().build());
  }

  @Bean
  OidcTokenRequestor tokenRequestor(RestTemplateFactory restTemplateFactory) {
    return new DefaultOidcTokenRequestor(restTemplateFactory);
  }
}
