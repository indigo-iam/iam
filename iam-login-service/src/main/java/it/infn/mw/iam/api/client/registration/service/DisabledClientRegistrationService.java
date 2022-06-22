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
package it.infn.mw.iam.api.client.registration.service;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.client.error.InvalidClientRegistrationRequest;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;

@Service
@ConditionalOnProperty(name = "client-registration.enable", havingValue = "false",
    matchIfMissing = false)
public class DisabledClientRegistrationService implements ClientRegistrationService {

  private static final Logger LOG =
      LoggerFactory.getLogger(DisabledClientRegistrationService.class);

  public static final String REGISTRATION_DISABLED_MSG =
      "Client registration is disabled";

  public DisabledClientRegistrationService() {
    LOG.info(REGISTRATION_DISABLED_MSG);
  }

  private RegisteredClientDTO registrationDisabled() {
    throw new InvalidClientRegistrationRequest(REGISTRATION_DISABLED_MSG);
  }

  @Override
  public RegisteredClientDTO registerClient(@Valid RegisteredClientDTO request,
      Authentication authentication) {
    return registrationDisabled();
  }

  @Override
  public RegisteredClientDTO retrieveClient(String clientId, Authentication authentication) {
    return registrationDisabled();
  }

  @Override
  public RegisteredClientDTO updateClient(String clientId, @Valid RegisteredClientDTO request,
      Authentication authentication) {
    return registrationDisabled();
  }

  @Override
  public void deleteClient(String clientId, Authentication authentication) {
    registrationDisabled();
  }

  @Override
  public RegisteredClientDTO redeemClient(@NotBlank String clientId,
      @NotBlank String registrationAccessToken, Authentication authentication) {
    return registrationDisabled();
  }
}
