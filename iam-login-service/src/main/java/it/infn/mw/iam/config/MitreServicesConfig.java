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
package it.infn.mw.iam.config;

import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.mitre.jwt.assertion.impl.SelfAssertionValidator;
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService;
import org.mitre.oauth2.service.impl.BlacklistAwareRedirectResolver;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.config.UIConfiguration;
import org.mitre.openid.connect.service.BlacklistedSiteService;
import org.mitre.openid.connect.service.ClientLogoLoadingService;
import org.mitre.openid.connect.service.LoginHintExtracter;
import org.mitre.openid.connect.service.PairwiseIdentiferService;
import org.mitre.openid.connect.service.WhitelistedSiteService;
import org.mitre.openid.connect.service.impl.DefaultBlacklistedSiteService;
import org.mitre.openid.connect.service.impl.DefaultWhitelistedSiteService;
import org.mitre.openid.connect.service.impl.InMemoryClientLogoLoadingService;
import org.mitre.openid.connect.service.impl.RemoveLoginHintsWithHTTP;
import org.mitre.openid.connect.service.impl.UUIDPairwiseIdentiferService;
import org.mitre.openid.connect.web.ServerConfigInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;

import com.google.common.collect.Sets;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.core.IamClientDetailsService;
import it.infn.mw.iam.core.client.ClientUserDetailsService;
import it.infn.mw.iam.core.client.IAMClientUserDetailsService;
import it.infn.mw.iam.core.jwk.IamJWKSetCacheService;
import it.infn.mw.iam.core.oauth.IamOAuth2RequestFactory;
import it.infn.mw.iam.core.oauth.device.DeviceCodeService;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherOAuthRequestValidator;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.repository.IamAuthorizationCodeRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@Configuration
public class MitreServicesConfig {

  @Value("${iam.issuer}")
  private String issuer;

  @Value("${iam.baseUrl}")
  private String baseUrl;

  @Value("${iam.token.lifetime}")
  private Long tokenLifeTime;

  @Value("${iam.topbarTitle}")
  private String topbarTitle;

  @Bean
  ConfigurationPropertiesBean config(IamProperties properties) {

    ConfigurationPropertiesBean config = new ConfigurationPropertiesBean();

    config.setLogoImageUrl(properties.getLogo().getUrl());
    config.setTopbarTitle(topbarTitle);

    if (!issuer.endsWith("/")) {
      issuer = issuer + "/";
    }

    config.setIssuer(issuer);

    if (tokenLifeTime <= 0L) {
      config.setRegTokenLifeTime(null);
    } else {
      config.setRegTokenLifeTime(tokenLifeTime);
    }

    config.setForceHttps(false);
    config.setLocale(Locale.ENGLISH);

    config
      .setAllowCompleteDeviceCodeUri(properties.getDeviceCode().getAllowCompleteVerificationUri());

    return config;
  }


  @Bean
  UIConfiguration uiConfiguration() {

    Set<String> jsFiles =
        Sets.newHashSet("resources/js/client.js", "resources/js/grant.js", "resources/js/scope.js",
            "resources/js/whitelist.js", "resources/js/dynreg.js", "resources/js/rsreg.js",
            "resources/js/token.js", "resources/js/blacklist.js", "resources/js/profile.js");

    UIConfiguration config = new UIConfiguration();
    config.setJsFiles(jsFiles);
    return config;

  }

  @Bean
  RedirectResolver blacklistAwareRedirectResolver() {

    return new BlacklistAwareRedirectResolver();
  }

  @Bean
  OAuth2RequestValidator requestValidator(ScopeMatcherRegistry registry) {

    return new ScopeMatcherOAuthRequestValidator(registry);
  }

  @Bean
  OAuth2RequestFactory requestFactory(ScopeFilter scopeFilter, JWTProfileResolver profileResolver,
      DeviceCodeService deviceCodeService, IamAuthorizationCodeRepository authzCodeRepository,
      IamOAuthRefreshTokenRepository refreshTokenRepo, ClientDetailsService clientDetailsService,
      ClientKeyCacheService validators) {
    return new IamOAuth2RequestFactory(clientDetailsService, scopeFilter, profileResolver,
        deviceCodeService, authzCodeRepository, refreshTokenRepo, validators);
  }

  @Bean(name = "iamClientDetailsEntityService")
  ClientDetailsService clientDetailsService(IamClientRepository clientRepo) {
    return new IamClientDetailsService(clientRepo);
  }

  @Bean(name = "mitreServerConfigInterceptor")
  ServerConfigInterceptor serverConfigInterceptor() {

    return new ServerConfigInterceptor();
  }

  @Bean
  Http403ForbiddenEntryPoint http403ForbiddenEntryPoint() {

    return new Http403ForbiddenEntryPoint();
  }

  @Bean
  OAuth2AuthenticationEntryPoint oauth2AuthenticationEntryPoint() {

    OAuth2AuthenticationEntryPoint entryPoint = new OAuth2AuthenticationEntryPoint();
    entryPoint.setRealmName("openidconnect");
    return entryPoint;
  }

  @Bean(name = "clientUserDetailsService")
  ClientUserDetailsService defaultClientUserDetailsService(ClientService clientService) {

    return new IAMClientUserDetailsService(clientService);
  }

  @Bean
  LoginHintExtracter defaultLoginHintExtracter() {

    return new RemoveLoginHintsWithHTTP();
  }

  @Bean
  ClientLogoLoadingService defaultClientLogoLoadingService() {

    return new InMemoryClientLogoLoadingService();
  }

  @Bean
  SymmetricKeyJWTValidatorCacheService defaultSimmetricKeyJWTValidatorCacheService() {

    return new SymmetricKeyJWTValidatorCacheService();
  }

  @Bean
  JWKSetCacheService defaultCacheService(RestTemplateFactory rtf) {

    return new IamJWKSetCacheService(rtf, 100, 1, TimeUnit.HOURS);
  }

  @Bean
  PairwiseIdentiferService defaultPairwiseIdentifierService() {

    return new UUIDPairwiseIdentiferService();
  }

  @Bean
  WhitelistedSiteService defaultWhitelistedSiteService() {

    return new DefaultWhitelistedSiteService();
  }

  @Bean
  BlacklistedSiteService defaultBlacklistedSiteService() {

    return new DefaultBlacklistedSiteService();
  }

  @Bean
  ClientKeyCacheService defaultClientKeyCacheService() {

    return new ClientKeyCacheService();
  }

  @Bean
  SelfAssertionValidator selfAssertionValidator() {
    return new SelfAssertionValidator();
  }
}
