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

import static it.infn.mw.iam.core.oauth.profile.ScopeAwareProfileResolver.AARC_PROFILE_ID;
import static it.infn.mw.iam.core.oauth.profile.ScopeAwareProfileResolver.IAM_PROFILE_ID;
import static it.infn.mw.iam.core.oauth.profile.ScopeAwareProfileResolver.WLCG_PROFILE_ID;

import java.time.Clock;
import java.util.Arrays;
import java.util.Map;

import org.h2.server.web.WebServlet;
import org.mitre.oauth2.service.IntrospectionResultAssembler;
import org.mitre.oauth2.service.impl.DefaultIntrospectionResultAssembler;
import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.mitre.openid.connect.service.UserInfoService;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import com.google.common.collect.Maps;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.AUPSignatureCheckService;
import it.infn.mw.iam.authn.ExternalAuthenticationInfoProcessor;
import it.infn.mw.iam.core.oauth.IamIntrospectionResultAssembler;
import it.infn.mw.iam.core.oauth.attributes.AttributeMapHelper;
import it.infn.mw.iam.core.oauth.profile.IamTokenEnhancer;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.profile.ScopeAwareProfileResolver;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcJWTProfile;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcJWTProfileAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcJWTProfileIdTokenCustomizer;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcJWTProfileTokenIntrospectionHelper;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcJWTProfileUserinfoHelper;
import it.infn.mw.iam.core.oauth.profile.common.BaseIntrospectionHelper;
import it.infn.mw.iam.core.oauth.profile.iam.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.iam.IamJWTProfile;
import it.infn.mw.iam.core.oauth.profile.iam.IamJWTProfileAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.iam.IamJWTProfileIdTokenCustomizer;
import it.infn.mw.iam.core.oauth.profile.iam.IamJWTProfileTokenIntrospectionHelper;
import it.infn.mw.iam.core.oauth.profile.iam.IamJWTProfileUserinfoHelper;
import it.infn.mw.iam.core.oauth.profile.wlcg.WLCGGroupHelper;
import it.infn.mw.iam.core.oauth.profile.wlcg.WLCGJWTProfile;
import it.infn.mw.iam.core.oauth.scope.matchers.DefaultScopeMatcherRegistry;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatchersProperties;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatchersPropertiesParser;
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
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;

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
  JWTProfile aarcJwtProfile(IamProperties props, IamAccountRepository accountRepo,
      ScopeClaimTranslationService converter, AarcClaimValueHelper claimHelper,
      UserInfoService userInfoService, ScopeMatcherRegistry registry) {

    AarcJWTProfileAccessTokenBuilder atBuilder =
        new AarcJWTProfileAccessTokenBuilder(props, converter, claimHelper);

    AarcJWTProfileUserinfoHelper uiHelper =
        new AarcJWTProfileUserinfoHelper(props, userInfoService, claimHelper);

    AarcJWTProfileIdTokenCustomizer idHelper =
        new AarcJWTProfileIdTokenCustomizer(accountRepo, converter, claimHelper, props);

    BaseIntrospectionHelper intrHelper = new AarcJWTProfileTokenIntrospectionHelper(props,
        new DefaultIntrospectionResultAssembler(), registry, claimHelper);

    return new AarcJWTProfile(atBuilder, idHelper, uiHelper, intrHelper);
  }

  @Bean(name = "iamJwtProfile")
  JWTProfile iamJwtProfile(IamProperties props, IamAccountRepository accountRepo,
      ScopeClaimTranslationService converter, ClaimValueHelper claimHelper,
      UserInfoService userInfoService, ExternalAuthenticationInfoProcessor proc,
      ScopeMatcherRegistry registry) {

    IamJWTProfileAccessTokenBuilder atBuilder =
        new IamJWTProfileAccessTokenBuilder(props, converter, claimHelper);

    IamJWTProfileUserinfoHelper uiHelper =
        new IamJWTProfileUserinfoHelper(props, userInfoService, proc);

    IamJWTProfileIdTokenCustomizer idHelper =
        new IamJWTProfileIdTokenCustomizer(accountRepo, converter, claimHelper, props);

    BaseIntrospectionHelper intrHelper = new IamJWTProfileTokenIntrospectionHelper(props,
        new DefaultIntrospectionResultAssembler(), registry);

    return new IamJWTProfile(atBuilder, idHelper, uiHelper, intrHelper);
  }

  @Bean(name = "wlcgJwtProfile")
  JWTProfile wlcgJwtProfile(IamProperties props, IamAccountRepository accountRepo,
      ScopeClaimTranslationService converter, AttributeMapHelper attributeMapHelper,
      UserInfoService userInfoService, ExternalAuthenticationInfoProcessor proc,
      ScopeMatcherRegistry registry, ScopeClaimTranslationService claimTranslationService,
      ClaimValueHelper claimValueHelper) {

    return new WLCGJWTProfile(props, userInfoService, accountRepo, new WLCGGroupHelper(),
        attributeMapHelper, new DefaultIntrospectionResultAssembler(), registry,
        claimTranslationService, claimValueHelper);
  }

  @Bean
  JWTProfileResolver jwtProfileResolver(@Qualifier("iamJwtProfile") JWTProfile iamProfile,
      @Qualifier("wlcgJwtProfile") JWTProfile wlcgProfile,
      @Qualifier("aarcJwtProfile") JWTProfile aarcProfile, IamProperties properties,
      ClientDetailsService clientDetailsService) {

    JWTProfile defaultProfile = iamProfile;

    if (it.infn.mw.iam.config.IamProperties.JWTProfile.Profile.WLCG
      .equals(properties.getJwtProfile().getDefaultProfile())) {
      defaultProfile = wlcgProfile;
    }

    if (it.infn.mw.iam.config.IamProperties.JWTProfile.Profile.AARC
      .equals(properties.getJwtProfile().getDefaultProfile())) {
      defaultProfile = aarcProfile;
    }

    Map<String, JWTProfile> profileMap = Maps.newHashMap();
    profileMap.put(IAM_PROFILE_ID, iamProfile);
    profileMap.put(WLCG_PROFILE_ID, wlcgProfile);
    profileMap.put(AARC_PROFILE_ID, aarcProfile);

    LOG.info("Default JWT profile: {}", defaultProfile.name());
    return new ScopeAwareProfileResolver(defaultProfile, profileMap, clientDetailsService);
  }

  @Bean
  Clock defaultClock() {
    return Clock.systemDefaultZone();
  }

  @Bean
  AuthorizationCodeServices authorizationCodeServices() {
    return new DefaultOAuth2AuthorizationCodeService();
  }

  @Bean
  @Primary
  TokenEnhancer iamTokenEnhancer() {
    return new IamTokenEnhancer();
  }

  @Bean
  IntrospectionResultAssembler defaultIntrospectionResultAssembler(
      JWTProfileResolver profileResolver) {
    return new IamIntrospectionResultAssembler(profileResolver);
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  FilterRegistrationBean<EnforceAupFilter> aupSignatureCheckFilter(AUPSignatureCheckService service,
      AccountUtils utils, IamAupRepository repo) {
    EnforceAupFilter aupFilter = new EnforceAupFilter(service, utils, repo);
    FilterRegistrationBean<EnforceAupFilter> frb =
        new FilterRegistrationBean<>(aupFilter);
    frb.setOrder(Ordered.LOWEST_PRECEDENCE);
    return frb;
  }



  @Bean
  ScopeMatcherRegistry customScopeMatchersRegistry(ScopeMatchersProperties properties) {
    ScopeMatchersPropertiesParser parser = new ScopeMatchersPropertiesParser();
    return new DefaultScopeMatcherRegistry(parser.parseScopeMatchersProperties(properties), 20);
  }

  @Bean
  @Profile("dev")
  ServletRegistrationBean<WebServlet> h2Console() {
    WebServlet h2Servlet = new WebServlet();
    return new ServletRegistrationBean<>(h2Servlet, "/h2-console/*");
  }

}
