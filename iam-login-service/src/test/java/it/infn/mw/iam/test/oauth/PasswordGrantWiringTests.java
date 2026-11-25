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
package it.infn.mw.iam.test.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.ReflectionUtils;

import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@SuppressWarnings("deprecation")
@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
class PasswordGrantWiringTests {

  @Autowired
  @Qualifier("passwordTokenGranter")
  ResourceOwnerPasswordTokenGranter granter;

  @Test
  void passwordGrantMustNotUseAnUncustomizedDaoProvider() {
    var field = ReflectionUtils.findField(ResourceOwnerPasswordTokenGranter.class, null,
        AuthenticationManager.class);
    assertNotNull(field, "Expected a manager on the Spring OAuth password granter");
    var manager = ReflectionTestUtils.getField(granter, field.getName());
    assertNotNull(manager);
    if (manager instanceof ProviderManager providers) {
      var plainDaoProviders = providers.getProviders()
        .stream()
        .filter(provider -> provider.getClass().equals(DaoAuthenticationProvider.class))
        .count();
      assertEquals(0L, plainDaoProviders,
          "Password grant delegates directly to a plain DAO provider without IAM login policy");
    }
  }
}
