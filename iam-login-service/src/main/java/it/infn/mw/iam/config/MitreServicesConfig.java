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

import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;

import com.google.common.collect.Sets;

import it.infn.mw.iam.authn.oidc.AuthorizationRequestFilter;
import it.infn.mw.iam.core.OAuth2TokenEntityService;
import it.infn.mw.iam.core.client.IamClientDetailsService;
import it.infn.mw.iam.core.oauth.IamOAuth2RequestFactory;
import it.infn.mw.iam.core.oauth.devicecode.DeviceCodeService;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherOAuthRequestValidator;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.repository.IamAuthorizationCodeRepository;

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
  MitreConfigurationPropertiesBean config(IamProperties properties) {

    return new MitreConfigurationPropertiesBean(properties);
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
  OAuth2RequestValidator requestValidator(ScopeMatcherRegistry registry) {

    return new ScopeMatcherOAuthRequestValidator(registry);
  }

  @Bean
  OAuth2RequestFactory requestFactory(IamClientDetailsService clientDetailsService,
      ScopeFilter scopeFilter, JWTProfileResolver profileResolver,
      DeviceCodeService deviceCodeService, IamAuthorizationCodeRepository authzCodeRepository,
      OAuth2TokenEntityService tokenServices) {
    return new IamOAuth2RequestFactory(clientDetailsService, scopeFilter, profileResolver,
        deviceCodeService, authzCodeRepository, tokenServices);
  }

  @Bean
  FilterRegistrationBean<AuthorizationRequestFilter> disabledMitreFilterRegistration(
      AuthorizationRequestFilter f) {

    FilterRegistrationBean<AuthorizationRequestFilter> b = new FilterRegistrationBean<>(f);
    b.setEnabled(false);
    // what ???
    return b;
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
}
