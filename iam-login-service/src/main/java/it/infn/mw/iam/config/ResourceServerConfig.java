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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgAccessTokenBuilder;
import it.infn.mw.iam.core.rs.IamAudienceAuthenticationManager;
import it.infn.mw.iam.core.web.wellknown.ProtectedResourceRegistry;

@SuppressWarnings("deprecation")
@Configuration
@Order(9) // This is important! Do not remove
public class ResourceServerConfig {
  
  @Autowired
  private OAuth2AuthenticationEntryPoint authenticationEntryPoint;

  @Autowired
  private ResourceServerTokenServices tokenService;

  @Autowired
  private IamProperties iamProperties;

  @Autowired
  private ProtectedResourceRegistry protectedResourceRegistry;

  @Bean
  FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> disabledAutomaticFilterRegistration(
      final OAuth2AuthenticationProcessingFilter f) {

    FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> b =
        new FilterRegistrationBean<>(f);
    b.setEnabled(false);
    return b;
  }

  @Bean(name = "resourceServerFilter")
  OAuth2AuthenticationProcessingFilter oauthResourceServerFilter() {

    OAuth2AuthenticationManager manager = new OAuth2AuthenticationManager();
    manager.setTokenServices(tokenService);

    OAuth2AuthenticationProcessingFilter filter = new OAuth2AuthenticationProcessingFilter();
    filter.setAuthenticationEntryPoint(authenticationEntryPoint);

    if (iamProperties.getResourceIndicators().isRequireIamAudience()) {
      filter.setAuthenticationManager(new IamAudienceAuthenticationManager(manager,
          Set.of(protectedResourceRegistry.iamResourceIdentifier(), iamProperties.getIssuer(),
              WlcgAccessTokenBuilder.ALL_AUDIENCES_VALUE)));
    } else {
      filter.setAuthenticationManager(manager);
    }
    filter.setStateless(false);
    return filter;
  }
  
}
