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

import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;

@SuppressWarnings("deprecation")
@Configuration
@EnableAuthorizationServer
public class IamAuthorizationServerConfigurer extends AuthorizationServerConfigurerAdapter {

  private final OAuth2TokenEntityService tokenService;
  private final ClientDetailsEntityService clientDetailsService;
  private final OAuth2RequestFactory requestFactory;
  private final AuthorizationCodeServices authorizationCodeServices;
  private final OAuth2RequestValidator requestValidator;
  private final UserApprovalHandler userApprovalHandler;
  private final TokenGranter tokenGranter;

  public IamAuthorizationServerConfigurer(OAuth2TokenEntityService tokenService,
      @Qualifier("iamClientDetailsEntityService") ClientDetailsEntityService clientDetailsService,
      OAuth2RequestFactory requestFactory, AuthorizationCodeServices authorizationCodeServices,
      OAuth2RequestValidator requestValidator,
      @Qualifier("iamUserApprovalHandler") UserApprovalHandler userApprovalHandler,
      TokenGranter tokenGranter) {

    this.tokenService = tokenService;
    this.clientDetailsService = clientDetailsService;
    this.requestFactory = requestFactory;
    this.authorizationCodeServices = authorizationCodeServices;
    this.requestValidator = requestValidator;
    this.userApprovalHandler = userApprovalHandler;
    this.tokenGranter = tokenGranter;
  }

  @Override
  public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

    endpoints.requestValidator(requestValidator)
      .pathMapping("/oauth/token", "/token")
      .pathMapping("/oauth/authorize", "/authorize")
      .tokenServices(tokenService)
      .userApprovalHandler(userApprovalHandler)
      .requestFactory(requestFactory)
      .tokenGranter(tokenGranter)
      .authorizationCodeServices(authorizationCodeServices);
  }

  @Override
  public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {

    clients.withClientDetails(clientDetailsService);
  }

  @Override
  public void configure(final AuthorizationServerSecurityConfigurer security) throws Exception {

    security.allowFormAuthenticationForClients();
  }
}
