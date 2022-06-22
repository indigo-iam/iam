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
package it.infn.mw.iam.api.client.service;

import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.IMPLICIT;
import static java.util.Objects.isNull;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.common.collect.Sets;

import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties;

@Service
public class DefaultClientDefaultsService implements ClientDefaultsService {

  private static final Set<AuthMethod> AUTH_METHODS_REQUIRING_SECRET =
      EnumSet.of(AuthMethod.SECRET_BASIC, AuthMethod.SECRET_POST, AuthMethod.SECRET_JWT);

  private static final int SECRET_SIZE = 512;
  private static final SecureRandom RNG = new SecureRandom();

  private final ClientRegistrationProperties properties;

  @Autowired
  public DefaultClientDefaultsService(ClientRegistrationProperties properties) {
    this.properties = properties;
  }

  @Override
  public ClientDetailsEntity setupClientDefaults(ClientDetailsEntity client) {

    if (isNull(client.getClientId())) {
      client.setClientId(UUID.randomUUID().toString());
    }

    client.setAccessTokenValiditySeconds(
        properties.getClientDefaults().getDefaultAccessTokenValiditySeconds());

    client
      .setIdTokenValiditySeconds(properties.getClientDefaults().getDefaultIdTokenValiditySeconds());

    client.setDeviceCodeValiditySeconds(
        properties.getClientDefaults().getDefaultDeviceCodeValiditySeconds());

    final int rtSecs = properties.getClientDefaults().getDefaultRefreshTokenValiditySeconds();

    if (rtSecs < 0) {
      client.setRefreshTokenValiditySeconds(null);
    } else {
      client.setRefreshTokenValiditySeconds(rtSecs);
    }

    if (client.getGrantTypes().contains(IMPLICIT.getGrantType()) || client.getGrantTypes()
      .contains(AuthorizationGrantType.CLIENT_CREDENTIALS.getGrantType())) {
      client.setRefreshTokenValiditySeconds(0);
    }

    client.setAllowIntrospection(true);

    if (isNull(client.getContacts())) {
      client.setContacts(new HashSet<>());
    }

    if (isNull(client.getClientId())) {
      client.setClientId(UUID.randomUUID().toString());
    }

    if (AUTH_METHODS_REQUIRING_SECRET.contains(client.getTokenEndpointAuthMethod())) {
      client.setClientSecret(generateClientSecret());
    }

    client.setAuthorities(Sets.newHashSet(Authorities.ROLE_CLIENT));

    return client;
  }

  @Override
  public String generateClientSecret() {
    return
        Base64.encodeBase64URLSafeString(new BigInteger(SECRET_SIZE, RNG).toByteArray())
          .replace("=", "");
  }

}
