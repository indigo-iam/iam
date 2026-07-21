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

import static java.util.Objects.isNull;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.springframework.stereotype.Service;

import com.google.common.collect.Sets;

import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.ClientProperties;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties;
import it.infn.mw.iam.core.client.IamHmacPasswordEncoder;
import it.infn.mw.iam.persistence.model.ClientAuthMethod;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.PKCEAlgorithm;

@Service
public class ClientUtils {

  public static final Set<ClientAuthMethod> AUTH_METHODS_REQUIRING_SECRET = Set
    .of(ClientAuthMethod.SECRET_BASIC, ClientAuthMethod.SECRET_POST, ClientAuthMethod.SECRET_JWT);

  private static final int SECRET_SIZE = 512;
  private static final int BCRYPT_MAX_SIZE = 72;
  private static final SecureRandom RNG = new SecureRandom();

  private final ClientRegistrationProperties registrationProperties;
  private final ClientProperties clientProperties;

  public ClientUtils(ClientRegistrationProperties registrationProperties,
      IamProperties iamProperties) {
    this.registrationProperties = registrationProperties;
    this.clientProperties = iamProperties.getClient();
  }

  public ClientDetailsEntity setupClientDefaults(ClientDetailsEntity client) {

    if (isNull(client.getClientId())) {
      client.setClientId(UUID.randomUUID().toString());
    }

    if (client.getAccessTokenValiditySeconds() == null
        || client.getAccessTokenValiditySeconds() == 0) {
      client.setAccessTokenValiditySeconds(
          registrationProperties.getClientDefaults().getDefaultAccessTokenValiditySeconds());
    }

    if (client.getRefreshTokenValiditySeconds() == null) {
      client.setRefreshTokenValiditySeconds(
          registrationProperties.getClientDefaults().getDefaultRefreshTokenValiditySeconds());
    }

    if (client.getIdTokenValiditySeconds() == null || client.getIdTokenValiditySeconds() == 0) {
      client.setIdTokenValiditySeconds(
          registrationProperties.getClientDefaults().getDefaultIdTokenValiditySeconds());
    }

    if (client.getDeviceCodeValiditySeconds() == null
        || client.getDeviceCodeValiditySeconds() == 0) {
      client.setDeviceCodeValiditySeconds(
          registrationProperties.getClientDefaults().getDefaultDeviceCodeValiditySeconds());
    }

    if (isNull(client.getTokenEndpointAuthMethod())) {
      client.setTokenEndpointAuthMethod(ClientAuthMethod.SECRET_BASIC);
    }

    if (isNull(client.getClientSecret())
        && AUTH_METHODS_REQUIRING_SECRET.contains(client.getTokenEndpointAuthMethod())) {
      client.setClientSecret(generateClientSecretHash());
    }

    client.setAuthorities(Sets.newHashSet(Authorities.ROLE_CLIENT));
    client.setCodeChallengeMethod(PKCEAlgorithm.OPTIONAL);
    return client;
  }

  public String generateClientSecretHash() {
    String clientSecret =
        Base64.encodeBase64URLSafeString(new BigInteger(SECRET_SIZE, RNG).toByteArray())
          .substring(0, BCRYPT_MAX_SIZE);

    return new IamHmacPasswordEncoder(clientProperties.getSecretEncoderKey()).encode(clientSecret);
  }

  public ClientDetailsEntity setupProtectedResourceDefaults(ClientDetailsEntity client) {

    client.setAccessTokenValiditySeconds(0);
    client.setRefreshTokenValiditySeconds(0);
    client.setIdTokenValiditySeconds(0);
    client.setDeviceCodeValiditySeconds(0);
    client.setGrantTypes(Set.of());
    client.setResponseTypes(Set.of());
    client.setRedirectUris(Set.of());
    client.setPostLogoutRedirectUris(Set.of());
    client.setActive(true);
    client.setDefaultACRvalues(Set.of());
    client.setDefaultMaxAge(null);
    client.setInitiateLoginUri(null);
    client.setRequestObjectSigningAlg(null);
    client.setRequireAuthTime(null);
    client.setReuseRefreshToken(false);
    client.setDynamicallyRegistered(true);
    client.setUpScopingEnabled(false);
    client.setCodeChallengeMethod(PKCEAlgorithm.NONE);
    if (isNull(client.getTokenEndpointAuthMethod())) {
      client.setTokenEndpointAuthMethod(ClientAuthMethod.SECRET_BASIC);
    }
    if (AUTH_METHODS_REQUIRING_SECRET.contains(client.getTokenEndpointAuthMethod())) {
      client.setClientSecret(generateClientSecretHash());
    } else {
      client.setClientSecret(null);
    }
    client.setAuthorities(Sets.newHashSet(Authorities.ROLE_CLIENT));
    return client;
  }
}
