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
package it.infn.mw.iam.core.oidc;

import java.net.URI;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.OAuthResponseType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;

public abstract class BaseFedClientRegistrationMapper {

  private static final Logger log = LoggerFactory.getLogger(BaseFedClientRegistrationMapper.class);

  public RegisteredClientDTO createClientDtoFromRpMetadata(EntityStatement rpRequest) {

    RegisteredClientDTO dtoClient = new RegisteredClientDTO();
    OIDCClientMetadata metadata = rpRequest.getClaimsSet().getRPMetadata();

    setClientName(dtoClient, metadata);
    setContacts(dtoClient, metadata);
    setGrantTypes(dtoClient, metadata);
    setRedirectUris(dtoClient, metadata);
    setResponseTypes(dtoClient, metadata);
    setTokenEndpointAuthMethod(dtoClient, metadata);
    setScope(dtoClient, metadata);
    setEntityId(dtoClient, rpRequest);
    setJwks(dtoClient, metadata);

    log.debug("Client metadata mapped successfully for RP: {}", dtoClient.getEntityId());
    return dtoClient;
  }

  protected abstract void setTokenEndpointAuthMethod(RegisteredClientDTO dto,
      OIDCClientMetadata metadata);

  protected void setClientName(RegisteredClientDTO dto, OIDCClientMetadata metadata) {
    dto.setClientName(Optional.ofNullable(metadata.getName()).orElse("OIDFed client"));
  }

  protected void setContacts(RegisteredClientDTO dto, OIDCClientMetadata metadata) {
    Optional.ofNullable(metadata.getEmailContacts())
      .ifPresent(c -> dto.setContacts(new HashSet<>(c)));
  }

  protected void setGrantTypes(RegisteredClientDTO dto, OIDCClientMetadata metadata) {
    Set<AuthorizationGrantType> grantTypes = Optional.ofNullable(metadata.getGrantTypes())
      .orElse(Set.of(GrantType.AUTHORIZATION_CODE))
      .stream()
      .map(GrantType::getValue)
      .map(AuthorizationGrantType::fromGrantType)
      .collect(Collectors.toSet());

    dto.setGrantTypes(grantTypes);
  }

  protected void setRedirectUris(RegisteredClientDTO dto, OIDCClientMetadata metadata) {
    if (metadata.getRedirectionURIs() == null || metadata.getRedirectionURIs().isEmpty()) {
      throw new InvalidClientMetadataException("invalid_redirect_uri", "Missing redirect URIs");
    }
    dto.setRedirectUris(
        metadata.getRedirectionURIs().stream().map(URI::toString).collect(Collectors.toSet()));
  }

  protected void setResponseTypes(RegisteredClientDTO dto, OIDCClientMetadata metadata) {
    Set<String> supportedResponseTypes =
        Set.of(ResponseType.CODE.toString(), ResponseType.TOKEN.toString());
    if (metadata.getResponseTypes() != null) {
      Set<OAuthResponseType> responseTypes = metadata.getResponseTypes()
        .stream()
        .map(ResponseType::toString)
        .filter(supportedResponseTypes::contains)
        .map(OAuthResponseType::fromResponseType)
        .collect(Collectors.toSet());
      if (responseTypes.isEmpty()) {
        throw new InvalidClientMetadataException("invalid_client_metadata",
            "Unsupported response type");
      }
      dto.setResponseTypes(responseTypes);
    } else {
      dto.setResponseTypes(Set.of(OAuthResponseType.CODE));
    }
  }

  protected void setScope(RegisteredClientDTO dto, OIDCClientMetadata metadata) {
    if (metadata.getScope() != null) {
      dto.setScope(metadata.getScope().toStringList().stream().collect(Collectors.toSet()));
    } else {
      dto.setScope(Set.of("openid"));
    }
  }

  protected void setEntityId(RegisteredClientDTO dto, EntityStatement rpRequest) {
    dto.setEntityId(rpRequest.getEntityID().getValue());
  }

  protected void setJwks(RegisteredClientDTO dto, OIDCClientMetadata metadata) {
    Optional.ofNullable(metadata.getJWKSetURI())
      .ifPresent(uri -> dto.setJwksUri(uri.toASCIIString()));

    Optional.ofNullable(metadata.getJWKSet()).ifPresent(jwk -> dto.setJwk(jwk.toString()));
  }
}
