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
import static java.util.stream.Collectors.toSet;

import java.text.ParseException;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.springframework.stereotype.Component;

import com.google.common.base.Strings;
import com.nimbusds.jose.jwk.JWKSet;

import it.infn.mw.iam.api.client.registration.ClientRegistrationApiController;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.OAuthResponseType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties;
import it.infn.mw.iam.persistence.model.IamClient;
import it.infn.mw.iam.persistence.model.IamClient.AuthMethod;
import it.infn.mw.iam.persistence.model.PKCEAlgorithm;

@Component
public class ClientConverter {

  private final IamProperties iamProperties;

  private final String clientRegistrationBaseUrl;
  private final ClientRegistrationProperties clientRegistrationProperties;

  public ClientConverter(IamProperties properties,
      ClientRegistrationProperties clientRegistrationProperties) {
    this.iamProperties = properties;
    this.clientRegistrationProperties = clientRegistrationProperties;
    clientRegistrationBaseUrl =
        String.format("%s%s", iamProperties.getBaseUrl(), ClientRegistrationApiController.ENDPOINT);
  }

  private <T> Set<T> cloneSet(Set<T> stringSet) {
    Set<T> result = new HashSet<>();
    if (stringSet != null) {
      result.addAll(stringSet);
    }
    return result;
  }


  public IamClient entityFromClientManagementRequest(RegisteredClientDTO dto)
      throws ParseException {
    IamClient client = entityFromRegistrationRequest(dto);

    if (dto.getAccessTokenValiditySeconds() != null && dto.getAccessTokenValiditySeconds() > 0) {
      client.setAccessTokenValiditySeconds(dto.getAccessTokenValiditySeconds());
    }
    // Refresh Token validity seconds zero value is valid and means infinite duration
    if (dto.getRefreshTokenValiditySeconds() != null && dto.getRefreshTokenValiditySeconds() >= 0) {
      client.setRefreshTokenValiditySeconds(dto.getRefreshTokenValiditySeconds());
    }
    if (dto.getIdTokenValiditySeconds() != null && dto.getIdTokenValiditySeconds() > 0) {
      client.setIdTokenValiditySeconds(dto.getIdTokenValiditySeconds());
    }
    if (dto.getDeviceCodeValiditySeconds() != null && dto.getDeviceCodeValiditySeconds() > 0) {
      client.setDeviceCodeValiditySeconds(dto.getDeviceCodeValiditySeconds());
    }

    client.setAllowIntrospection(dto.isAllowIntrospection());
    client.setReuseRefreshToken(dto.isReuseRefreshToken());
    client.setClearAccessTokensOnRefresh(dto.isClearAccessTokensOnRefresh());

    if (dto.getCodeChallengeMethod() != null) {
      PKCEAlgorithm pkceAlgo = PKCEAlgorithm.parse(dto.getCodeChallengeMethod());
      client.setCodeChallengeMethod(pkceAlgo);
    }

    if (dto.getTokenEndpointAuthMethod() != null) {
      client
        .setTokenEndpointAuthMethod(AuthMethod.getByValue(dto.getTokenEndpointAuthMethod().name()));
    }

    client.setRequireAuthTime(Boolean.valueOf(dto.isRequireAuthTime()));

    return client;
  }



  public RegisteredClientDTO registeredClientDtoFromEntity(IamClient entity) {
    RegisteredClientDTO clientDTO = new RegisteredClientDTO();

    clientDTO.setClientId(entity.getClientId());
    clientDTO.setClientSecret(entity.getClientSecret());
    clientDTO.setClientName(entity.getClientName());
    clientDTO.setContacts(entity.getContacts());
    clientDTO.setGrantTypes(entity.getGrantTypes()
      .stream()
      .map(AuthorizationGrantType::fromGrantType)
      .collect(toSet()));

    clientDTO.setJwksUri(entity.getJwksUri());
    clientDTO.setRedirectUris(cloneSet(entity.getRedirectUris()));

    clientDTO.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod
      .valueOf(Optional.ofNullable(entity.getTokenEndpointAuthMethod())
        .orElse(AuthMethod.NONE)
        .getValue()));

    clientDTO.setScope(cloneSet(entity.getScope()));
    clientDTO.setTosUri(entity.getTosUri());

    clientDTO.setCreatedAt(entity.getCreatedAt());
    if (entity.getClientLastUsed() != null) {
      clientDTO.setLastUsed(entity.getClientLastUsed().getLastUsed());
    }
    clientDTO.setAccessTokenValiditySeconds(entity.getAccessTokenValiditySeconds());
    clientDTO.setAllowIntrospection(entity.isAllowIntrospection());
    clientDTO.setClearAccessTokensOnRefresh(entity.isClearAccessTokensOnRefresh());
    clientDTO.setClientDescription(entity.getClientDescription());
    clientDTO.setClientUri(entity.getClientUri());
    clientDTO.setDeviceCodeValiditySeconds(entity.getDeviceCodeValiditySeconds());
    clientDTO.setDynamicallyRegistered(entity.isDynamicallyRegistered());
    clientDTO.setIdTokenValiditySeconds(entity.getIdTokenValiditySeconds());
    clientDTO.setJwksUri(entity.getJwksUri());

    Optional.ofNullable(entity.getJwks()).ifPresent(k -> clientDTO.setJwk(k.toString()));
    clientDTO.setPolicyUri(entity.getPolicyUri());
    clientDTO.setRefreshTokenValiditySeconds(entity.getRefreshTokenValiditySeconds());

    Optional.ofNullable(entity.getResponseTypes())
      .ifPresent(rts -> clientDTO
        .setResponseTypes(rts.stream().map(OAuthResponseType::fromResponseType).collect(toSet())));

    clientDTO.setReuseRefreshToken(entity.isReuseRefreshToken());

    if (entity.isDynamicallyRegistered()) {
      clientDTO.setRegistrationClientUri(
          String.format("%s/%s", clientRegistrationBaseUrl, entity.getClientId()));
    }

    if (entity.getCodeChallengeMethod() != null) {
      clientDTO.setCodeChallengeMethod(entity.getCodeChallengeMethod().getName());
    }

    if (entity.getRequireAuthTime() != null) {
      clientDTO.setRequireAuthTime(entity.getRequireAuthTime());
    } else {
      clientDTO.setRequireAuthTime(false);
    }

    clientDTO.setActive(entity.isActive());
    clientDTO.setStatusChangedOn(entity.getStatusChangedOn());
    clientDTO.setStatusChangedBy(entity.getStatusChangedBy());

    return clientDTO;
  }

  public IamClient entityFromRegistrationRequest(RegisteredClientDTO dto)
      throws ParseException {

    IamClient client = new IamClient();

    client.setClientId(dto.getClientId());
    client.setClientDescription(dto.getClientDescription());
    client.setClientName(dto.getClientName());
    client.setClientSecret(dto.getClientSecret());

    client.setClientUri(dto.getClientUri());

    if (!Strings.isNullOrEmpty(dto.getJwksUri())) {
      client.setJwksUri(dto.getJwksUri());
    } else if (!Strings.isNullOrEmpty(dto.getJwk())) {
      client.setJwks(JWKSet.parse(dto.getJwk()));
    }

    client.setPolicyUri(dto.getPolicyUri());
    
    client.setRedirectUris(cloneSet(dto.getRedirectUris()));

    client.setScope(cloneSet(dto.getScope()));
    
    client.setGrantTypes(new HashSet<>());   

    if (!isNull(dto.getGrantTypes())) {
      client.setGrantTypes(
          dto.getGrantTypes()
          .stream()
          .map(AuthorizationGrantType::getGrantType)
          .collect(toSet()));
    }

    if (dto.getScope().contains("offline_access")) {
      client.getGrantTypes().add(AuthorizationGrantType.REFRESH_TOKEN.getGrantType());
    }

    if (!isNull(dto.getResponseTypes())) {
      client.setResponseTypes(
          dto.getResponseTypes().stream().map(OAuthResponseType::getResponseType).collect(toSet()));
    }

    client.setContacts(cloneSet(dto.getContacts()));

    if (!isNull(dto.getTokenEndpointAuthMethod())) {
      client
        .setTokenEndpointAuthMethod(AuthMethod.getByValue(dto.getTokenEndpointAuthMethod().name()));
    }

    if (dto.getCodeChallengeMethod() != null) {
      PKCEAlgorithm pkceAlgo = PKCEAlgorithm.parse(dto.getCodeChallengeMethod());
      client.setCodeChallengeMethod(pkceAlgo);
    }

    // bypasses MitreID default setting to zero inside client's entity
    client.setAccessTokenValiditySeconds(clientRegistrationProperties.getClientDefaults().getDefaultAccessTokenValiditySeconds());
    client.setRefreshTokenValiditySeconds(clientRegistrationProperties.getClientDefaults().getDefaultRefreshTokenValiditySeconds());
    client.setIdTokenValiditySeconds(clientRegistrationProperties.getClientDefaults().getDefaultIdTokenValiditySeconds());
    client.setDeviceCodeValiditySeconds(clientRegistrationProperties.getClientDefaults().getDefaultDeviceCodeValiditySeconds());

    return client;
  }

  public RegisteredClientDTO registrationResponseFromClient(IamClient entity) {
    RegisteredClientDTO response = registeredClientDtoFromEntity(entity);
    response.setRegistrationClientUri(
        String.format("%s/%s", clientRegistrationBaseUrl, entity.getClientId()));

    return response;
  }

}