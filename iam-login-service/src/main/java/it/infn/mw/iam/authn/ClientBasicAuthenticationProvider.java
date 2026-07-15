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
package it.infn.mw.iam.authn;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.persistence.model.ClientAuthMethod;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

public class ClientBasicAuthenticationProvider implements AuthenticationProvider {

  private static final Logger LOG =
      LoggerFactory.getLogger(ClientBasicAuthenticationProvider.class);

  private final AuthenticationProvider delegate;
  private final ClientService clientService;

  public ClientBasicAuthenticationProvider(AuthenticationProvider delegate,
      ClientService clientService) {
    this.delegate = delegate;
    this.clientService = clientService;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    Optional<ClientDetailsEntity> client =
        clientService.findClientByClientId(authentication.getName());

    if (client.isEmpty()) {
      LOG.debug("Client with id {} was not found", authentication.getName());
      throw new BadCredentialsException("Bad client credentials");
    }

    ClientAuthMethod tokenAuthnMethod = client.get().getTokenEndpointAuthMethod();

    if (tokenAuthnMethod == ClientAuthMethod.NONE) {
      if (client.get().getClientSecret() != null) {

        LOG.debug("Public client with id {} has a not-null secret", client.get().getClientId());
        throw new AuthenticationServiceException("Public client requires no secret");
      }
      if (authentication.getCredentials() == null
          || "".equals(String.valueOf(authentication.getCredentials()))) {
        return new UsernamePasswordAuthenticationToken(client.get().getClientId(), null,
            client.get().getAuthorities());
      }
      throw new AuthenticationServiceException("Public client requires no secret");
    }

    if (!(tokenAuthnMethod == ClientAuthMethod.SECRET_BASIC
        || tokenAuthnMethod == ClientAuthMethod.SECRET_POST)) {

      LOG.debug("Client with id {} does not support basic authentication",
          client.get().getClientId());
      throw new AuthenticationServiceException("Client does not support basic authentication");
    }

    return delegate.authenticate(authentication);
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return delegate.supports(authentication);
  }

}
