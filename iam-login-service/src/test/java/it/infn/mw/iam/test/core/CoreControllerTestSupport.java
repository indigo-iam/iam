/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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

import java.time.Instant;

import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;

import it.infn.mw.iam.test.util.MockTimeProvider;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@Configuration
public class CoreControllerTestSupport {
  public static final Instant NOW = Instant.parse("2019-01-01T00:00:00.00Z");

  @Primary
  @Bean(name = "resourceServerFilter")
  MockOAuth2Filter mockOAuth2Filter(OAuth2AuthenticationEntryPoint entryPoint) {

    return new MockOAuth2Filter();
  }

  @Bean
  @Primary
  MockTimeProvider mockTimeProvider() {
    return new MockTimeProvider();
  }

  @Bean
  @Primary
  ApplicationEventPublisher mockApplicationEventPublisher() {
    return Mockito.mock(ApplicationEventPublisher.class);
  }

}
