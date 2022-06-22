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

import org.mitre.oauth2.repository.AuthenticationHolderRepository;
import org.mitre.oauth2.repository.AuthorizationCodeRepository;
import org.mitre.oauth2.repository.OAuth2ClientRepository;
import org.mitre.oauth2.repository.OAuth2TokenRepository;
import org.mitre.oauth2.repository.SystemScopeRepository;
import org.mitre.oauth2.repository.impl.DeviceCodeRepository;
import org.mitre.oauth2.repository.impl.JpaAuthenticationHolderRepository;
import org.mitre.oauth2.repository.impl.JpaAuthorizationCodeRepository;
import org.mitre.oauth2.repository.impl.JpaDeviceCodeRepository;
import org.mitre.oauth2.repository.impl.JpaOAuth2TokenRepository;
import org.mitre.oauth2.repository.impl.JpaSystemScopeRepository;
import org.mitre.openid.connect.repository.ApprovedSiteRepository;
import org.mitre.openid.connect.repository.BlacklistedSiteRepository;
import org.mitre.openid.connect.repository.PairwiseIdentifierRepository;
import org.mitre.openid.connect.repository.UserInfoRepository;
import org.mitre.openid.connect.repository.WhitelistedSiteRepository;
import org.mitre.openid.connect.repository.impl.JpaApprovedSiteRepository;
import org.mitre.openid.connect.repository.impl.JpaBlacklistedSiteRepository;
import org.mitre.openid.connect.repository.impl.JpaPairwiseIdentifierRepository;
import org.mitre.openid.connect.repository.impl.JpaWhitelistedSiteRepository;
import org.mitre.openid.connect.service.impl.MITREidDataService_1_3;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import it.infn.mw.iam.persistence.repository.IamUserinfoRepository;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.persistence.repository.client.IamOAuth2ClientRepositoryAdapter;

@Configuration
public class MitreRepositoryConfig {

  @Bean
  AuthenticationHolderRepository authenticationHolderRepository() {

    return new JpaAuthenticationHolderRepository();
  }

  @Bean
  AuthorizationCodeRepository authorizationCodeRepository() {

    return new JpaAuthorizationCodeRepository();
  }

  @Bean
  PairwiseIdentifierRepository defaultPairwiseIdentifierRepository() {

    return new JpaPairwiseIdentifierRepository();
  }

  @Bean
  UserInfoRepository defaultUserInfoRepository() {

    return new IamUserinfoRepository();
  }

  @Bean
  OAuth2ClientRepository defaultOAuth2ClientRepository(IamClientRepository clientRepo,
      IamAccountClientRepository accountClientRepo) {
    return new IamOAuth2ClientRepositoryAdapter(clientRepo, accountClientRepo);
  }

  @Bean
  OAuth2TokenRepository defaultOAuth2TokenRepository() {

    return new JpaOAuth2TokenRepository();
  }

  @Bean
  ApprovedSiteRepository defaultApprovedSiteRepository() {

    return new JpaApprovedSiteRepository();
  }

  @Bean
  WhitelistedSiteRepository defaultWhitelistedSiteRepository() {

    return new JpaWhitelistedSiteRepository();
  }

  @Bean
  BlacklistedSiteRepository defaultBlacklistedSiteRepository() {

    return new JpaBlacklistedSiteRepository();
  }

  @Bean
  SystemScopeRepository defaultSystemScopeRepository() {

    return new JpaSystemScopeRepository();
  }

  @Bean
  DeviceCodeRepository deviceCodeRepository() {
    return new JpaDeviceCodeRepository();
  }
  
  @Bean
  MITREidDataService_1_3 dataService13() {
    return new MITREidDataService_1_3();
  }
}
