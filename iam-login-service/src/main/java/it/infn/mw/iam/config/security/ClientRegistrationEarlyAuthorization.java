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
package it.infn.mw.iam.config.security;

import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy.ADMINISTRATORS;
import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy.ANYONE;
import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy.REGISTERED_USERS;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties;

/** Shared body-independent DCR policy for the HTTP filter chain and registration service. */
@Component("clientRegistrationEarlyAuthorization")
public class ClientRegistrationEarlyAuthorization {

  private final ClientRegistrationProperties properties;
  private final AccountUtils accountUtils;

  public ClientRegistrationEarlyAuthorization(ClientRegistrationProperties properties,
      AccountUtils accountUtils) {
    this.properties = properties;
    this.accountUtils = accountUtils;
  }

  public boolean canRegister(Authentication authentication) {
    return isAllowed(properties, accountUtils, authentication);
  }

  public static boolean isAllowed(ClientRegistrationProperties properties,
      AccountUtils accountUtils, Authentication authentication) {
    var policy = properties.getAllowFor();
    return (ADMINISTRATORS.equals(policy) && accountUtils.isAdmin(authentication))
        || (REGISTERED_USERS.equals(policy) && accountUtils.isRegisteredUser(authentication))
        || ANYONE.equals(policy);
  }
}
