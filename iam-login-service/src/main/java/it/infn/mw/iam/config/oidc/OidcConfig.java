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

import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.openid.connect.client.service.IssuerService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.authn.AuthenticationSuccessHandlerHelper;
import it.infn.mw.iam.authn.ExternalAuthenticationFailureHandler;
import it.infn.mw.iam.authn.ExternalAuthenticationSuccessHandler;
import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.common.config.AuthenticationValidator;
import it.infn.mw.iam.authn.oidc.ClientConfigurationService;
import it.infn.mw.iam.authn.oidc.DefaultClientConfigurationService;
import it.infn.mw.iam.authn.oidc.DefaultOidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.DefaultRestTemplateFactory;
import it.infn.mw.iam.authn.oidc.OIDCAuthenticationFilter;
import it.infn.mw.iam.authn.oidc.OIDCAuthenticationProvider;
import it.infn.mw.iam.authn.oidc.OIDCAuthenticationToken;
import it.infn.mw.iam.authn.oidc.OidcExceptionMessageHelper;
import it.infn.mw.iam.authn.oidc.OidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.PlainAuthRequestUrlBuilder;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.service.OIDCProviderMetadataService;
import it.infn.mw.iam.authn.oidc.service.OidcAccountProvisioningService;
import it.infn.mw.iam.authn.oidc.service.UserInfoFetcher;
import it.infn.mw.iam.authn.util.SessionTimeoutHelper;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.IamThirdPartyIssuerService;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

@Configuration
@EnableConfigurationProperties(IamOidcJITAccountProvisioningProperties.class)
public class OidcConfig {

  @Value("${iam.baseUrl}")
  private String iamBaseUrl;

  public static final String DEFINE_ME_PLEASE = "define_me_please";

  @Bean
  FilterRegistrationBean<OIDCAuthenticationFilter> disabledAutomaticOidcFilterRegistration(
      OIDCAuthenticationFilter f) {

    FilterRegistrationBean<OIDCAuthenticationFilter> b = new FilterRegistrationBean<>(f);
    b.setEnabled(false);
    return b;
  }

  @Bean
  ClientConfigurationService clientConfigurationService(OidcProviderProperties oidcProperties) {
    return new DefaultClientConfigurationService(oidcProperties);
  }

  @Bean(name = "OIDCAuthenticationFilter")
  OIDCAuthenticationFilter openIdConnectAuthenticationFilterCanl(
      JWKSetCacheService validationServices, IssuerService issuerService,
      OIDCProviderMetadataService servers, ClientConfigurationService clientConfigurationService,
      PlainAuthRequestUrlBuilder authRequestBuilder, Clock clock, OidcTokenRequestor tokenRequestor,
      Environment env, ObjectMapper objectMapper,
      @Qualifier("OIDCAuthenticationManager") AuthenticationManager oidcAuthenticationManager,
      @Qualifier("OIDCExternalAuthenticationSuccessHandler") AuthenticationSuccessHandler successHandler,
      @Qualifier("OIDCExternalAuthenticationFailureHandler") AuthenticationFailureHandler failureHandler) {

    OIDCAuthenticationFilter filter = new OIDCAuthenticationFilter(validationServices,
        issuerService, servers, clientConfigurationService, authRequestBuilder, clock,
        tokenRequestor, env, objectMapper, 300);
    filter.setAuthenticationManager(oidcAuthenticationManager);
    filter.setAuthenticationSuccessHandler(successHandler);
    filter.setAuthenticationFailureHandler(failureHandler);

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
  OIDCAuthenticationProvider openIdConnectAuthenticationProvider(
      AuthenticationValidator<OIDCAuthenticationToken> tokenValidatorService,
      SessionTimeoutHelper sessionTimeoutHelper, IamAccountRepository accountRepo,
      InactiveAccountAuthenticationHander inactiveAccountHandler,
      IamTotpMfaRepository totpMfaRepository, IamOidcJITAccountProvisioningProperties jitProperties,
      OidcAccountProvisioningService oidcProvisioningService,
      IamTotpMfaProperties iamTotpMfaProperties, UserInfoFetcher userInfoFetcher) {

    return new OIDCAuthenticationProvider(tokenValidatorService, sessionTimeoutHelper, accountRepo,
        inactiveAccountHandler, totpMfaRepository, jitProperties, oidcProvisioningService,
        iamTotpMfaProperties, userInfoFetcher);
  }

  @Bean
  IssuerService oidcIssuerService() {

    return new IamThirdPartyIssuerService();
  }

  @Bean
  OidcTokenRequestor tokenRequestor(RestTemplateFactory restTemplateFactory, ObjectMapper mapper) {
    return new DefaultOidcTokenRequestor(restTemplateFactory, mapper);
  }

}
