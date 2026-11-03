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
package it.infn.mw.iam.test.api.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy;
import it.infn.mw.iam.config.security.ClientRegistrationEarlyAuthorization;

class ClientRegistrationEarlyAuthorizationTests {

  private final ClientRegistrationProperties properties = new ClientRegistrationProperties();
  private final AccountUtils accountUtils = mock(AccountUtils.class);
  private final ClientRegistrationEarlyAuthorization authorization =
      new ClientRegistrationEarlyAuthorization(properties, accountUtils);
  private final Authentication authentication = mock(Authentication.class);

  @Test
  void anyoneAllowsAnonymousRegistration() {
    properties.setAllowFor(ClientRegistrationAuthorizationPolicy.ANYONE);
    assertTrue(authorization.canRegister(null));
  }

  @Test
  void registeredUsersPolicyRejectsAnonymousAndAllowsRegisteredUser() {
    properties.setAllowFor(ClientRegistrationAuthorizationPolicy.REGISTERED_USERS);
    assertFalse(authorization.canRegister(null));
    when(accountUtils.isRegisteredUser(authentication)).thenReturn(true);
    assertTrue(authorization.canRegister(authentication));
  }

  @Test
  void administratorsPolicyRequiresAdmin() {
    properties.setAllowFor(ClientRegistrationAuthorizationPolicy.ADMINISTRATORS);
    assertFalse(authorization.canRegister(authentication));
    when(accountUtils.isAdmin(authentication)).thenReturn(true);
    assertTrue(authorization.canRegister(authentication));
  }
}
