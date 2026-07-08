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

import org.mitre.oauth2.repository.SystemScopeRepository;
import org.mitre.oauth2.repository.impl.JpaSystemScopeRepository;
import org.mitre.openid.connect.repository.BlacklistedSiteRepository;
import org.mitre.openid.connect.repository.PairwiseIdentifierRepository;
import org.mitre.openid.connect.repository.UserInfoRepository;
import org.mitre.openid.connect.repository.WhitelistedSiteRepository;
import org.mitre.openid.connect.repository.impl.JpaBlacklistedSiteRepository;
import org.mitre.openid.connect.repository.impl.JpaPairwiseIdentifierRepository;
import org.mitre.openid.connect.repository.impl.JpaWhitelistedSiteRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import it.infn.mw.iam.persistence.repository.IamUserinfoRepository;

@Configuration
public class MitreRepositoryConfig {

  @Bean
  PairwiseIdentifierRepository defaultPairwiseIdentifierRepository() {

    return new JpaPairwiseIdentifierRepository();
  }

  @Bean
  UserInfoRepository defaultUserInfoRepository() {

    return new IamUserinfoRepository();
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
}
