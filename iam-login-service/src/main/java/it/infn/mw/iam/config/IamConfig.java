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

import java.time.Clock;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.h2.server.web.WebServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.session.web.http.DefaultCookieSerializer;

import com.google.common.collect.Maps;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.authn.oidc.DefaultRestTemplateFactory;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.configuration.DynamicServerConfigurationService;
import it.infn.mw.iam.authn.oidc.configuration.ServerConfigurationService;
import it.infn.mw.iam.core.OAuth2TokenEntityService;
import it.infn.mw.iam.core.jwt.IamJwkSetCacheService;
import it.infn.mw.iam.core.jwt.JwkSetCacheService;
import it.infn.mw.iam.core.jwt.assertion.AssertionOAuth2RequestFactory;
import it.infn.mw.iam.core.jwt.assertion.AssertionValidator;
import it.infn.mw.iam.core.oauth.attributes.AttributeMapHelper;
import it.infn.mw.iam.core.oauth.devicecode.DeviceCodeService;
import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdp;
import it.infn.mw.iam.core.oauth.granters.ChainedTokenGranter;
import it.infn.mw.iam.core.oauth.granters.IamAuthorizationCodeTokenGranter;
import it.infn.mw.iam.core.oauth.granters.IamClientCredentialsTokenGranter;
import it.infn.mw.iam.core.oauth.granters.IamDeviceCodeTokenGranter;
import it.infn.mw.iam.core.oauth.granters.IamImplicitTokenGranter;
import it.infn.mw.iam.core.oauth.granters.IamRefreshTokenGranter;
import it.infn.mw.iam.core.oauth.granters.IamResourceOwnerPasswordTokenGranter;
import it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.profile.ScopeAwareProfileResolver;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcIdTokenCustomizer;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcIntrospectionHelper;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcJWTProfile;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcScopeClaimTranslationService;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcUserinfoHelper;
import it.infn.mw.iam.core.oauth.profile.iam.IamAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.iam.IamClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.iam.IamIdTokenCustomizer;
import it.infn.mw.iam.core.oauth.profile.iam.IamIntrospectionHelper;
import it.infn.mw.iam.core.oauth.profile.iam.IamJWTProfile;
import it.infn.mw.iam.core.oauth.profile.iam.IamScopeClaimTranslationService;
import it.infn.mw.iam.core.oauth.profile.iam.IamUserinfoHelper;
import it.infn.mw.iam.core.oauth.profile.keycloak.KeycloakAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.keycloak.KeycloakClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.keycloak.KeycloakIdTokenCustomizer;
import it.infn.mw.iam.core.oauth.profile.keycloak.KeycloakIntrospectionHelper;
import it.infn.mw.iam.core.oauth.profile.keycloak.KeycloakJWTProfile;
import it.infn.mw.iam.core.oauth.profile.keycloak.KeycloakScopeClaimTranslationService;
import it.infn.mw.iam.core.oauth.profile.keycloak.KeycloakUserinfoHelper;
import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgIdTokenCustomizer;
import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgIntrospectionHelper;
import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgJWTProfile;
import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgScopeClaimTranslationService;
import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgUserinfoHelper;
import it.infn.mw.iam.core.oauth.scope.matchers.DefaultScopeMatcherRegistry;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatchersProperties;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatchersPropertiesParser;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.core.token.JwtAssertionTokenGranter;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.util.IamAuthenticationEventPublisher;
import it.infn.mw.iam.core.web.aup.EnforceAupFilter;
import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.notification.service.resolver.AddressResolutionService;
import it.infn.mw.iam.notification.service.resolver.AdminNotificationDeliveryStrategy;
import it.infn.mw.iam.notification.service.resolver.CompositeAdminsNotificationDelivery;
import it.infn.mw.iam.notification.service.resolver.GroupManagerNotificationDeliveryStrategy;
import it.infn.mw.iam.notification.service.resolver.NotifyAdminAddressStrategy;
import it.infn.mw.iam.notification.service.resolver.NotifyAdminsStrategy;
import it.infn.mw.iam.notification.service.resolver.NotifyGmStrategy;
import it.infn.mw.iam.notification.service.resolver.NotifyGmsAndAdminsStrategy;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamSystemScopeRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.registration.validation.UsernameValidator;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;

@SuppressWarnings("deprecation")
@Configuration
public class IamConfig {

  public static final Logger LOG = LoggerFactory.getLogger(IamConfig.class);

  @Value("${iam.organisation.name}")
  private String iamOrganisationName;

  @Bean
  GroupManagerNotificationDeliveryStrategy gmDeliveryStrategy(
      AdminNotificationDeliveryStrategy ands, AddressResolutionService ars,
      NotificationProperties props) {
    switch (props.getGroupManagerNotificationPolicy()) {
      case NOTIFY_GMS:
        return new NotifyGmStrategy(ars);
      case NOTIFY_GMS_AND_ADMINS:
        return new NotifyGmsAndAdminsStrategy(ands, ars);
      default:
        throw new IllegalArgumentException("Unhandled group manager notification policy: "
            + props.getGroupManagerNotificationPolicy());
    }
  }

  @Bean
  AdminNotificationDeliveryStrategy adminNotificationDeliveryStrategy(AddressResolutionService ars,
      NotificationProperties props) {

    switch (props.getAdminNotificationPolicy()) {
      case NOTIFY_ADDRESS:
        return new NotifyAdminAddressStrategy(props);
      case NOTIFY_ADMINS:
        return new NotifyAdminsStrategy(ars);
      case NOTIFY_ADDRESS_AND_ADMINS:
        return new CompositeAdminsNotificationDelivery(
            Arrays.asList(new NotifyAdminsStrategy(ars), new NotifyAdminsStrategy(ars)));

      default:
        throw new IllegalArgumentException(
            "Unhandled admin notification policy: " + props.getAdminNotificationPolicy());
    }
  }

  @Bean(name = "aarcJwtProfile")
  JWTProfile aarcJwtProfile(IamProperties properties, SshKeyConverter sshConverter,
      AttributeMapHelper attrHelper, IamTotpMfaRepository totpMfaRepository,
      AccountUtils accountUtils, ScopeFilter scopeFilter, IamAccountService accountService) {

    AarcScopeClaimTranslationService claimService = new AarcScopeClaimTranslationService();

    AarcClaimValueHelper claimValueHelper =
        new AarcClaimValueHelper(properties, sshConverter, attrHelper, claimService);

    AarcAccessTokenBuilder accessTokenBuilder = new AarcAccessTokenBuilder(properties,
        totpMfaRepository, accountUtils, scopeFilter, claimValueHelper, claimService);

    AarcIdTokenCustomizer idTokenCustomizer =
        new AarcIdTokenCustomizer(properties, claimValueHelper, claimService);

    AarcUserinfoHelper userInfoHelper =
        new AarcUserinfoHelper(properties, claimValueHelper, claimService);

    AarcIntrospectionHelper introspectionHelper =
        new AarcIntrospectionHelper(claimValueHelper, accountService);

    return new AarcJWTProfile(claimService, claimValueHelper, accessTokenBuilder, idTokenCustomizer,
        userInfoHelper, introspectionHelper);
  }

  @Bean(name = "kcJwtProfile")
  JWTProfile kcJwtProfile(IamProperties properties, SshKeyConverter sshConverter,
      AttributeMapHelper attrHelper, IamTotpMfaRepository totpMfaRepository,
      AccountUtils accountUtils, ScopeFilter scopeFilter, IamAccountService accountService) {

    KeycloakScopeClaimTranslationService claimService = new KeycloakScopeClaimTranslationService();

    KeycloakClaimValueHelper claimValueHelper =
        new KeycloakClaimValueHelper(properties, sshConverter, attrHelper, claimService);

    KeycloakAccessTokenBuilder accessTokenBuilder = new KeycloakAccessTokenBuilder(properties,
        totpMfaRepository, accountUtils, scopeFilter, claimValueHelper, claimService);

    KeycloakIdTokenCustomizer idTokenCustomizer =
        new KeycloakIdTokenCustomizer(properties, claimValueHelper, claimService);

    KeycloakUserinfoHelper userInfoHelper =
        new KeycloakUserinfoHelper(properties, claimValueHelper, claimService);

    KeycloakIntrospectionHelper introspectionHelper =
        new KeycloakIntrospectionHelper(accountService);

    return new KeycloakJWTProfile(claimService, claimValueHelper, accessTokenBuilder,
        idTokenCustomizer, userInfoHelper, introspectionHelper);
  }

  @Bean(name = "iamJwtProfile")
  JWTProfile iamJwtProfile(IamProperties properties, SshKeyConverter sshConverter,
      AttributeMapHelper attrHelper, IamTotpMfaRepository totpMfaRepository,
      AccountUtils accountUtils, ScopeFilter scopeFilter, IamAccountService accountService) {

    IamScopeClaimTranslationService scopeClaimService = new IamScopeClaimTranslationService();

    IamClaimValueHelper claimValueHelper =
        new IamClaimValueHelper(properties, sshConverter, attrHelper, scopeClaimService);

    IamAccessTokenBuilder accessTokenBuilder = new IamAccessTokenBuilder(properties,
        totpMfaRepository, accountUtils, scopeFilter, claimValueHelper, scopeClaimService);

    IamIdTokenCustomizer idTokenCustomizer =
        new IamIdTokenCustomizer(properties, claimValueHelper, scopeClaimService);

    IamUserinfoHelper userInfoHelper =
        new IamUserinfoHelper(properties, claimValueHelper, scopeClaimService);

    IamIntrospectionHelper introspectionHelper = new IamIntrospectionHelper(accountService);

    return new IamJWTProfile(scopeClaimService, claimValueHelper, accessTokenBuilder,
        idTokenCustomizer, userInfoHelper, introspectionHelper);
  }

  @Bean(name = "wlcgJwtProfile")
  JWTProfile wlcgJwtProfile(IamProperties properties, SshKeyConverter sshConverter,
      AttributeMapHelper attrHelper, IamTotpMfaRepository totpMfaRepository,
      AccountUtils accountUtils, ScopeFilter scopeFilter, IamAccountService accountService) {

    WlcgScopeClaimTranslationService claimService = new WlcgScopeClaimTranslationService();

    WlcgClaimValueHelper claimValueHelper =
        new WlcgClaimValueHelper(properties, sshConverter, attrHelper, claimService);

    WlcgAccessTokenBuilder accessTokenBuilder = new WlcgAccessTokenBuilder(properties,
        totpMfaRepository, accountUtils, scopeFilter, claimValueHelper, claimService);

    WlcgIdTokenCustomizer idTokenCustomizer =
        new WlcgIdTokenCustomizer(properties, claimValueHelper, claimService);

    WlcgUserinfoHelper userInfoHelper =
        new WlcgUserinfoHelper(properties, claimValueHelper, claimService);

    WlcgIntrospectionHelper introspectionHelper = new WlcgIntrospectionHelper(accountService);

    return new WlcgJWTProfile(claimService, claimValueHelper, accessTokenBuilder, idTokenCustomizer,
        userInfoHelper, introspectionHelper);
  }

  @Bean
  JWTProfileResolver jwtProfileResolver(@Qualifier("iamJwtProfile") JWTProfile iamProfile,
      @Qualifier("wlcgJwtProfile") JWTProfile wlcgProfile,
      @Qualifier("aarcJwtProfile") JWTProfile aarcProfile,
      @Qualifier("kcJwtProfile") JWTProfile kcProfile, IamProperties properties) {

    JWTProfile defaultProfile = iamProfile;

    if (IamProperties.JWTProfile.Profile.WLCG
      .equals(properties.getJwtProfile().getDefaultProfile())) {
      defaultProfile = wlcgProfile;
    }

    if (IamProperties.JWTProfile.Profile.AARC
      .equals(properties.getJwtProfile().getDefaultProfile())) {
      defaultProfile = aarcProfile;
    }

    if (IamProperties.JWTProfile.Profile.KC
      .equals(properties.getJwtProfile().getDefaultProfile())) {
      defaultProfile = kcProfile;
    }

    Map<String, JWTProfile> profileMap = Maps.newHashMap();
    profileMap.put(iamProfile.id(), iamProfile);
    profileMap.put(wlcgProfile.id(), wlcgProfile);
    profileMap.put(aarcProfile.id(), aarcProfile);
    profileMap.put(kcProfile.id(), kcProfile);

    LOG.info("Default JWT profile: {}", defaultProfile.name());
    return new ScopeAwareProfileResolver(defaultProfile, profileMap);
  }

  @Bean
  Clock defaultClock() {
    return Clock.systemDefaultZone();
  }

  // @Bean
  // AuthorizationCodeServices authorizationCodeServices(IamAuthorizationCodeRepository repository,
  // AuthenticationHolderEntityService authenticationHolderService) {
  // return new IamAuthorizationCodeService(repository, authenticationHolderService);
  // }

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  FilterRegistrationBean<EnforceAupFilter> aupSignatureCheckFilter(AUPSignatureCheckService service,
      AccountUtils utils, IamAupRepository repo) {
    EnforceAupFilter aupFilter = new EnforceAupFilter(service, utils, repo);
    FilterRegistrationBean<EnforceAupFilter> frb = new FilterRegistrationBean<>(aupFilter);
    frb.setOrder(Ordered.LOWEST_PRECEDENCE);
    return frb;
  }

  @Bean
  ScopeMatcherRegistry customScopeMatchersRegistry(ScopeMatchersProperties properties,
      IamSystemScopeRepository scopeRepo) {
    ScopeMatchersPropertiesParser parser = new ScopeMatchersPropertiesParser();
    return new DefaultScopeMatcherRegistry(parser.parseScopeMatchersProperties(properties),
        scopeRepo);
  }

  @Bean
  @Profile({"dev", "h2-console"})
  ServletRegistrationBean<WebServlet> h2Console() {
    WebServlet h2Servlet = new WebServlet();
    return new ServletRegistrationBean<>(h2Servlet, "/h2-console/*");
  }

  @Bean
  UsernameValidator usernameRegExpValidator() {
    return new UsernameValidator();
  }

  @Bean(destroyMethod = "shutdown")
  ScheduledExecutorService taskScheduler() {
    return Executors.newSingleThreadScheduledExecutor();
  }

  @Bean
  DefaultCookieSerializer defaultCookieSerializer() {
    DefaultCookieSerializer cs = new DefaultCookieSerializer();
    cs.setSameSite(null);
    return cs;
  }

  @Bean
  JwkSetCacheService defaultCacheService(RestTemplateFactory rtf) {

    return new IamJwkSetCacheService(rtf, 100, 1, TimeUnit.HOURS);
  }

  @Bean
  WebResponseExceptionTranslator<OAuth2Exception> webResponseExceptionTranslator() {

    return new DefaultWebResponseExceptionTranslator();
  }

  @Bean(name = "iamAuthenticationEventPublisher")
  AuthenticationEventPublisher iamAuthenticationEventPublisher() {
    return new IamAuthenticationEventPublisher();
  }

  @Bean(name = "authenticationManager")
  @Primary
  AuthenticationManager authenticationManager(UserDetailsService iamUserDetailsService,
      PasswordEncoder passwordEncoder) {

    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(iamUserDetailsService);
    provider.setPasswordEncoder(passwordEncoder);

    ProviderManager pm =
        new ProviderManager(Collections.<AuthenticationProvider>singletonList(provider));

    pm.setAuthenticationEventPublisher(iamAuthenticationEventPublisher());
    return pm;
  }

  @Bean
  TokenGranter tokenGranter(
      @Qualifier("authenticationManager") AuthenticationManager authenticationManager,
      UserDetailsService iamUserDetailsService, PasswordEncoder passwordEncoder,
      OAuth2TokenEntityService tokenServices, ClientDetailsService clientDetailsService,
      OAuth2RequestFactory requestFactory, AccountUtils accountUtils,
      AUPSignatureCheckService signatureCheckService, TokenExchangePdp tokenExchangePdp,
      AuthorizationCodeServices authorizationCodeServices, AssertionValidator assertionValidator,
      AssertionOAuth2RequestFactory assertionFactory, DeviceCodeService deviceCodeService) {

    IamResourceOwnerPasswordTokenGranter resourceOwnerPasswordCredentialGranter =
        new IamResourceOwnerPasswordTokenGranter(authenticationManager, tokenServices,
            clientDetailsService, requestFactory, signatureCheckService, accountUtils);

    IamRefreshTokenGranter refreshTokenGranter = new IamRefreshTokenGranter(tokenServices,
        clientDetailsService, requestFactory, signatureCheckService, accountUtils);

    TokenExchangeTokenGranter tokenExchangeGranter =
        new TokenExchangeTokenGranter(tokenServices, clientDetailsService, requestFactory);

    tokenExchangeGranter.setAccountUtils(accountUtils);
    tokenExchangeGranter.setSignatureCheckService(signatureCheckService);
    tokenExchangeGranter.setExchangePdp(tokenExchangePdp);

    return new CompositeTokenGranter(Arrays.<TokenGranter>asList(
        new IamAuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices,
            clientDetailsService, requestFactory),
        new IamImplicitTokenGranter(tokenServices, clientDetailsService, requestFactory),
        refreshTokenGranter,
        new IamClientCredentialsTokenGranter(tokenServices, clientDetailsService, requestFactory),
        resourceOwnerPasswordCredentialGranter,
        new JwtAssertionTokenGranter(tokenServices, clientDetailsService, requestFactory,
            assertionValidator, assertionFactory),
        new ChainedTokenGranter(tokenServices, clientDetailsService, requestFactory),
        tokenExchangeGranter, new IamDeviceCodeTokenGranter(tokenServices, clientDetailsService,
            requestFactory, deviceCodeService)));
  }

  @Bean
  FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> disabledAutomaticFilterRegistration(
      OAuth2AuthenticationProcessingFilter f) {

    FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> b =
        new FilterRegistrationBean<>(f);
    b.setEnabled(false);
    return b;
  }

  @Bean
  OAuth2AuthenticationProcessingFilter oauthResourceServerFilter(
      OAuth2AuthenticationEntryPoint authenticationEntryPoint,
      OAuth2TokenEntityService tokenService) {

    OAuth2AuthenticationManager manager = new OAuth2AuthenticationManager();
    manager.setTokenServices(tokenService);

    OAuth2AuthenticationProcessingFilter filter = new OAuth2AuthenticationProcessingFilter();
    filter.setAuthenticationEntryPoint(authenticationEntryPoint);
    filter.setAuthenticationManager(manager);
    filter.setStateless(false);
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

//  @Bean
//  HttpClient httpClient() {
//    return HttpClientBuilder.create().useSystemProperties().build();
//  }
}
