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

import java.util.Arrays;
import java.util.Collections;

import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.DeviceCodeService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.oauth2.token.ChainedTokenGranter;
import org.mitre.oauth2.token.JWTAssertionTokenGranter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.AUPSignatureCheckService;
import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdp;
import it.infn.mw.iam.core.oauth.granters.IamDeviceCodeTokenGranter;
import it.infn.mw.iam.core.oauth.granters.IamResourceOwnerPasswordTokenGranter;
import it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter;
import it.infn.mw.iam.core.util.IamAuthenticationEventPublisher;

@SuppressWarnings("deprecation")
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

  @Autowired
  @Qualifier("iamUserDetailsService")
  private UserDetailsService iamUserDetailsService;

  @Autowired
  private OAuth2TokenEntityService tokenServices;

  @Autowired
  @Qualifier("iamClientDetailsEntityService")
  private ClientDetailsEntityService clientDetailsService;

  @Autowired
  private OAuth2RequestFactory requestFactory;

  @Autowired
  private AuthorizationCodeServices authorizationCodeServices;

  @Autowired
  private OAuth2RequestValidator requestValidator;

  @Autowired
  private UserApprovalHandler approvalHandler;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Autowired
  private DeviceCodeService deviceCodeService;

  @Autowired
  private AccountUtils accountUtils;

  @Autowired
  private AUPSignatureCheckService signatureCheckService;
  
  @Autowired
  private TokenExchangePdp tokenExchangePdp;

  @Bean
  WebResponseExceptionTranslator<OAuth2Exception> webResponseExceptionTranslator() {

    return new DefaultWebResponseExceptionTranslator();
  }

  @Bean(name = "iamAuthenticationEventPublisher")
  AuthenticationEventPublisher iamAuthenticationEventPublisher() {
    return new IamAuthenticationEventPublisher();
  }

  @Bean(name = "authenticationManager")
  AuthenticationManager authenticationManager() {

    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(iamUserDetailsService);
    provider.setPasswordEncoder(passwordEncoder);

    ProviderManager pm =
        new ProviderManager(Collections.<AuthenticationProvider>singletonList(provider));

    pm.setAuthenticationEventPublisher(iamAuthenticationEventPublisher());
    return pm;

  }

  @Bean
  public TokenGranter tokenGranter() {

    AuthenticationManager authenticationManager = authenticationManager();

    IamResourceOwnerPasswordTokenGranter resourceOwnerPasswordCredentialGranter =
        new IamResourceOwnerPasswordTokenGranter(authenticationManager, tokenServices,
            clientDetailsService, requestFactory);

    resourceOwnerPasswordCredentialGranter.setAccountUtils(accountUtils);
    resourceOwnerPasswordCredentialGranter.setSignatureCheckService(signatureCheckService);

    TokenExchangeTokenGranter tokenExchangeGranter = new TokenExchangeTokenGranter(tokenServices,
        clientDetailsService, requestFactory);

    tokenExchangeGranter.setAccountUtils(accountUtils);
    tokenExchangeGranter.setSignatureCheckService(signatureCheckService);
    tokenExchangeGranter.setExchangePdp(tokenExchangePdp);

    return new CompositeTokenGranter(Arrays.<TokenGranter>asList(
        new AuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices,
            clientDetailsService, requestFactory),
        new ImplicitTokenGranter(tokenServices, clientDetailsService, requestFactory),
        new RefreshTokenGranter(tokenServices, clientDetailsService, requestFactory),
        new ClientCredentialsTokenGranter(tokenServices, clientDetailsService, requestFactory),
        resourceOwnerPasswordCredentialGranter,
        new JWTAssertionTokenGranter(tokenServices, clientDetailsService, requestFactory),
        new ChainedTokenGranter(tokenServices, clientDetailsService, requestFactory),
        tokenExchangeGranter, new IamDeviceCodeTokenGranter(tokenServices, clientDetailsService,
            requestFactory, deviceCodeService)));
  }

  @Override
  public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

    // @formatter:off
    endpoints
      .requestValidator(requestValidator)
      .pathMapping("/oauth/token", "/token")
      .pathMapping("/oauth/authorize", "/authorize")
      .tokenServices(tokenServices)
      .userApprovalHandler(approvalHandler)
      .requestFactory(requestFactory)
      .tokenGranter(tokenGranter())
      .authorizationCodeServices(authorizationCodeServices);
    // @formatter:on
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
