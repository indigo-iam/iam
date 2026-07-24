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
package it.infn.mw.iam.core.authn;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.client.ClientUserDetailsService;
import it.infn.mw.iam.core.client.IamHmacPasswordEncoder;
import it.infn.mw.iam.persistence.model.ClientAuthMethod;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

@SuppressWarnings("deprecation")
@Component
public class TokenEndpointBasicAuthenticationProvider extends DaoAuthenticationProvider {

  private final ClientService clientService;

  public TokenEndpointBasicAuthenticationProvider(
      @Qualifier("clientUserDetailsService") ClientUserDetailsService userDetailsService,
      IamProperties properties) {

    this
      .setPasswordEncoder(new IamHmacPasswordEncoder(properties.getClient().getSecretEncoderKey()));
    this.setUserDetailsService(userDetailsService);
    this.clientService = userDetailsService.getClientDetailsService();
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    String clientId = URLDecoder.decode(authentication.getName(), StandardCharsets.UTF_8);

    ClientDetailsEntity client = clientService.findClientByClientId(clientId)
      .orElseThrow(
          () -> new BadCredentialsException("Client with id " + clientId + " was not found"));

    if (ClientAuthMethod.NONE.equals(client.getTokenEndpointAuthMethod())) {
      if (client.getClientSecret() != null) {

        throw new AuthenticationServiceException("Public client requires no secret");
      }
      if (authentication.getCredentials() == null
          || "".equals(String.valueOf(authentication.getCredentials()))) {
        return new UsernamePasswordAuthenticationToken(client.getClientId(), null,
            client.getAuthorities());
      }
    }

    if (!supportsBasic(client)) {
      throw new BadCredentialsException("Client does not support basic authentication");
    }

    if (ClientAuthMethod.SECRET_BASIC.equals(client.getTokenEndpointAuthMethod())) {
      String clientSecret =
          URLDecoder.decode(authentication.getCredentials().toString(), StandardCharsets.UTF_8);

      return super.authenticate(new UsernamePasswordAuthenticationToken(clientId, clientSecret));
    }

    return super.authenticate(authentication);
  }

  private boolean supportsBasic(ClientDetailsEntity c) {
    return ClientAuthMethod.SECRET_BASIC.equals(c.getTokenEndpointAuthMethod())
        || ClientAuthMethod.NONE.equals(c.getTokenEndpointAuthMethod());
  }
}
