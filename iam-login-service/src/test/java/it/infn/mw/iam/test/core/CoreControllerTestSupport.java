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
package it.infn.mw.iam.test.core;

import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;

import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;
import it.infn.mw.iam.test.util.oauth.MockOAuthSecurityContextService;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SuppressWarnings("deprecation")
@TestConfiguration
public class CoreControllerTestSupport {

  @Primary
  @Bean(name = "resourceServerFilter")
  MockOAuth2Filter mockOAuth2Filter(OAuth2AuthenticationEntryPoint entryPoint) {
    return new MockOAuth2Filter();
  }

  @Bean
  MockOAuthSecurityContextService mockOAuthSecurityContextService(MockOAuth2Filter filter) {
    return new MockOAuthSecurityContextService(filter);
  }

  @Bean
  @Primary
  ApplicationEventPublisher mockApplicationEventPublisher() {
    return Mockito.mock(ApplicationEventPublisher.class);
  }

  @Bean
  SecurityContextUtils securityContextUtils(MockOAuth2Filter authFilter,
      MockOAuthSecurityContextService securityService) {

    return new SecurityContextUtils(authFilter, securityService);
  }
}
