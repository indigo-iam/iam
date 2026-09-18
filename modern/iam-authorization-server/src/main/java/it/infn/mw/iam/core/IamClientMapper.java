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
package it.infn.mw.iam.core;

import java.time.Duration;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.persistence.client.model.ClientAuthMethod;
import it.infn.mw.iam.persistence.client.model.ClientDetailsEntity;

@Component
public class IamClientMapper {

  public RegisteredClient toRegisteredClient(ClientDetailsEntity client) {

    RegisteredClient.Builder builder = RegisteredClient.withId(String.valueOf(client.getId()))
      .clientId(client.getClientId())
      .clientSecret(client.getClientSecret())
      .clientName(client.getClientName());

    client.getGrantTypes()
      .forEach(grantType -> builder.authorizationGrantType(new AuthorizationGrantType(grantType)));

    client.getRedirectUris().forEach(builder::redirectUri);

    client.getScope().forEach(builder::scope);

    switch (client.getTokenEndpointAuthMethod()) {
      case SECRET_BASIC -> builder
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

      case SECRET_POST -> builder
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);

      case PRIVATE_KEY -> builder
        .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);

      case NONE -> builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);

      default -> throw new IllegalArgumentException(
          "Unsupported client authentication method: " + client.getTokenEndpointAuthMethod());
    }

    if (client.getPostLogoutRedirectUris() != null) {
      client.getPostLogoutRedirectUris().forEach(builder::postLogoutRedirectUri);
    }

    ClientSettings.Builder clientSettingsBuilder =
        ClientSettings.builder().requireProofKey(client.getCodeChallengeMethod() != null);

    if (client.getJwksUri() != null && !client.getJwksUri().isBlank()) {
      clientSettingsBuilder.jwkSetUrl(client.getJwksUri());
    }

    ClientSettings clientSettings = clientSettingsBuilder.build();

    TokenSettings.Builder tokenSettingsBuilder =
        TokenSettings.builder().reuseRefreshTokens(client.isReuseRefreshToken());

    if (client.getAccessTokenValiditySeconds() != null
        && client.getAccessTokenValiditySeconds() > 0) {
      tokenSettingsBuilder
        .accessTokenTimeToLive(Duration.ofSeconds(client.getAccessTokenValiditySeconds()));
    }

    if (client.getRefreshTokenValiditySeconds() != null
        && client.getRefreshTokenValiditySeconds() > 0) {
      tokenSettingsBuilder
        .refreshTokenTimeToLive(Duration.ofSeconds(client.getRefreshTokenValiditySeconds()));
    }

    return builder.clientSettings(clientSettings)
      .tokenSettings(tokenSettingsBuilder.build())
      .build();
  }

  public ClientDetailsEntity toIamClient(RegisteredClient registeredClient) {

    ClientDetailsEntity client = new ClientDetailsEntity();

    if (registeredClient.getId() != null) {
      client.setId(Long.valueOf(registeredClient.getId()));
    }

    client.setClientId(registeredClient.getClientId());
    client.setClientSecret(registeredClient.getClientSecret());
    client.setClientName(registeredClient.getClientName());

    client.setRedirectUris(registeredClient.getRedirectUris());
    client.setScope(registeredClient.getScopes());

    client.setGrantTypes(registeredClient.getAuthorizationGrantTypes()
      .stream()
      .map(AuthorizationGrantType::getValue)
      .collect(Collectors.toSet()));

    client.setTokenEndpointAuthMethod(toClientAuthMethod(registeredClient));

    /*
     * RegisteredClient -> ClientDetailsEntity is currently partial. Additional legacy/OIDC fields
     * can be mapped later.
     */
    if (registeredClient.getClientSettings().isRequireProofKey()) {
      // The exact PKCE algorithm is not represented by RegisteredClient
    }

    String jwkSetUrl = registeredClient.getClientSettings().getJwkSetUrl();
    if (jwkSetUrl != null && !jwkSetUrl.isBlank()) {
      client.setJwksUri(jwkSetUrl);
    }

    client.setReuseRefreshToken(registeredClient.getTokenSettings().isReuseRefreshTokens());

    client.setAccessTokenValiditySeconds(Math
      .toIntExact(registeredClient.getTokenSettings().getAccessTokenTimeToLive().getSeconds()));

    client.setRefreshTokenValiditySeconds(Math
      .toIntExact(registeredClient.getTokenSettings().getRefreshTokenTimeToLive().getSeconds()));

    return client;
  }

  private ClientAuthMethod toClientAuthMethod(RegisteredClient registeredClient) {

    Set<ClientAuthenticationMethod> methods = registeredClient.getClientAuthenticationMethods();

    if (methods.size() != 1) {
      throw new IllegalArgumentException(
          "Expected exactly one client authentication method for client "
              + registeredClient.getClientId() + ", found: " + methods);
    }

    ClientAuthenticationMethod method = methods.iterator().next();

    if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(method)) {
      return ClientAuthMethod.SECRET_BASIC;
    }

    if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(method)) {
      return ClientAuthMethod.SECRET_POST;
    }

    if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(method)) {
      return ClientAuthMethod.PRIVATE_KEY;
    }

    if (ClientAuthenticationMethod.NONE.equals(method)) {
      return ClientAuthMethod.NONE;
    }

    throw new IllegalArgumentException("Unsupported client authentication method: " + method);
  }
}
