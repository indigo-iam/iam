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

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import it.infn.mw.iam.core.jwt.JwkSetCacheService;
import it.infn.mw.iam.core.jwt.JwtSigningAndValidationService;
import it.infn.mw.iam.core.jwt.assertion.AssertionOAuth2RequestFactory;
import it.infn.mw.iam.core.jwt.assertion.AssertionValidator;
import it.infn.mw.iam.core.jwt.assertion.DirectCopyRequestFactory;
import it.infn.mw.iam.core.jwt.assertion.SelfAssertionValidator;
import it.infn.mw.iam.core.jwt.assertion.WhitelistedIssuerAssertionValidator;

@Configuration
public class AssertionConfig {

  @Bean
  AssertionOAuth2RequestFactory jwtAssertionTokenFactory() {
    return new DirectCopyRequestFactory();
  }

  @Bean
  @Qualifier("clientAssertionValidator")
  AssertionValidator clientAssertionValidator(JwkSetCacheService jwkSetCacheService) {
    Map<String, String> whitelist = new LinkedHashMap<>();
    whitelist.put("http://artemesia.local", "http://localhost:8080/jwk");

    WhitelistedIssuerAssertionValidator validator =
        new WhitelistedIssuerAssertionValidator(jwkSetCacheService);
    validator.setWhitelist(whitelist);

    return validator;
  }

  @Bean
  @Primary
  @Qualifier("selfAssertionValidator")
  AssertionValidator selfAssertionValidator(IamProperties properties,
      JwtSigningAndValidationService jwtService) {

    return new SelfAssertionValidator(properties, jwtService);
  }
}
