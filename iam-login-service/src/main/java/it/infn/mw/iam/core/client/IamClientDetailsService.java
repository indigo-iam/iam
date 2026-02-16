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
package it.infn.mw.iam.core.client;

import static java.lang.String.format;

import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.repository.IamClientRepository;

@SuppressWarnings("deprecation")
@Service
public class IamClientDetailsService implements ClientDetailsService {

  public static final String CLIENT_NOT_FOUND_ERROR = "Client %s not found";
  public static final String CLIENT_DISABLED_ERROR = "Client %s is not active";

  private IamClientRepository clientRepository;

  public IamClientDetailsService(IamClientRepository clientRepository) {

    this.clientRepository = clientRepository;
  }

  /**
   * Load a client by the client id. This method must not return null.
   *
   * @param clientId The client id.
   * @return The client details (never null).
   * @throws ClientRegistrationException If the client account is locked, expired, disabled, or
   *         invalid for any other reason.
   */
  @Override
  public ClientDetailsEntity loadClientByClientId(String clientId)
      throws ClientRegistrationException {

    ClientDetailsEntity client = clientRepository.findByClientId(clientId)
      .orElseThrow(() -> new NoSuchClientException(format(CLIENT_NOT_FOUND_ERROR, clientId)));

    if (!client.isActive()) {
      throw new InvalidClientException(format(CLIENT_DISABLED_ERROR, clientId));
    }

    return client;
  }

}
