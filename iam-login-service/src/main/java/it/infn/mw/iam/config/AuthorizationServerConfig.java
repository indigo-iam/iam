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
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdp;
import it.infn.mw.iam.core.oauth.granters.IamDeviceCodeTokenGranter;
import it.infn.mw.iam.core.oauth.granters.IamRefreshTokenGranter;
import it.infn.mw.iam.core.oauth.granters.IamResourceOwnerPasswordTokenGranter;
import it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter;
import it.infn.mw.iam.core.util.IamAuthenticationEventPublisher;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;

@SuppressWarnings("deprecation")
@Configuration
public class AuthorizationServerConfig {

  @Bean
  WebResponseExceptionTranslator<OAuth2Exception> webResponseExceptionTranslator() {

    return new DefaultWebResponseExceptionTranslator();
  }

  @Bean(name = "iamAuthenticationEventPublisher")
  AuthenticationEventPublisher iamAuthenticationEventPublisher() {
    return new IamAuthenticationEventPublisher();
  }

  @Bean(name = "authenticationManager")
  AuthenticationManager authenticationManager(
      @Qualifier("iamUserDetailsService") UserDetailsService userDetailsService,
      PasswordEncoder passwordEncoder) {

    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(userDetailsService);
    provider.setPasswordEncoder(passwordEncoder);

    ProviderManager pm =
        new ProviderManager(Collections.<AuthenticationProvider>singletonList(provider));

    pm.setAuthenticationEventPublisher(iamAuthenticationEventPublisher());
    return pm;

  }

  @Bean
  TokenGranter tokenGranter(IamAccountRepository accountRepository,
      OAuth2TokenEntityService tokenService,
      @Qualifier("iamClientDetailsEntityService") ClientDetailsEntityService clientDetailsService,
      OAuth2RequestFactory requestFactory, AuthenticationManager authenticationManager,
      DeviceCodeService deviceCodeService, AuthorizationCodeServices authorizationCodeServices,
      AccountUtils accountUtils, AUPSignatureCheckService signatureCheckService,
      TokenExchangePdp tokenExchangePdp) {

    IamResourceOwnerPasswordTokenGranter resourceOwnerPasswordCredentialGranter =
        new IamResourceOwnerPasswordTokenGranter(authenticationManager, tokenService,
            clientDetailsService, requestFactory);

    resourceOwnerPasswordCredentialGranter.setAccountUtils(accountUtils);
    resourceOwnerPasswordCredentialGranter.setSignatureCheckService(signatureCheckService);

    IamRefreshTokenGranter refreshTokenGranter =
        new IamRefreshTokenGranter(tokenService, clientDetailsService, requestFactory);
    refreshTokenGranter.setAccountUtils(accountUtils);
    refreshTokenGranter.setSignatureCheckService(signatureCheckService);

    TokenExchangeTokenGranter tokenExchangeGranter =
        new TokenExchangeTokenGranter(tokenService, clientDetailsService, requestFactory,
            signatureCheckService, tokenExchangePdp, accountRepository);

    return new CompositeTokenGranter(Arrays.<TokenGranter>asList(
        new AuthorizationCodeTokenGranter(tokenService, authorizationCodeServices,
            clientDetailsService, requestFactory),
        new ImplicitTokenGranter(tokenService, clientDetailsService, requestFactory),
        refreshTokenGranter,
        new ClientCredentialsTokenGranter(tokenService, clientDetailsService, requestFactory),
        resourceOwnerPasswordCredentialGranter,
        new JWTAssertionTokenGranter(tokenService, clientDetailsService, requestFactory),
        new ChainedTokenGranter(tokenService, clientDetailsService, requestFactory),
        tokenExchangeGranter, new IamDeviceCodeTokenGranter(tokenService, clientDetailsService,
            requestFactory, deviceCodeService)));
  }



}
