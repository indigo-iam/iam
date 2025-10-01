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
package it.infn.mw.iam.api.openid_federation;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.mitre.jose.keystore.JWKSetKeyStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.OAuthResponseType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.core.jwk.JWKUtils;

@Service
@Profile("openid-federation")
public class FederationResponseBuilder {

  @Value("${iam.issuer}")
  private String opEntityId;

  private final JWSSigner signer;
  private final RSAKey signingKey;
  private static final JWSAlgorithm alg = JWSAlgorithm.RS256;

  public FederationResponseBuilder(JWKSetKeyStore keyStore) {
    this.signingKey = keyStore.getKeys()
      .stream()
      .filter(k -> k instanceof RSAKey && k.isPrivate())
      .map(k -> (RSAKey) k)
      .findFirst()
      .orElseThrow(() -> new IllegalStateException("No private RSA key found"));

    try {
      this.signer = JWKUtils.buildSigner(signingKey)
        .orElseThrow(() -> new IllegalStateException("Cannot build signer from key"));
    } catch (JOSEException e) {
      throw new IllegalStateException("Failed to build signer", e);
    }
  }

  public String build(RegisteredClientDTO registered, TrustChain trustChain) throws JOSEException {

    Date iat = new Date();

    Date exp = registered.getExpiration();

    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer(opEntityId)
      .subject(trustChain.getLeafSelfStatement().getClaimsSet().getSubject().getValue())
      .issueTime(iat)
      .expirationTime(exp)
      .audience(trustChain.getLeafSelfStatement().getClaimsSet().getSubject().getValue());

    claims.claim("trust_anchor", trustChain.getTrustAnchorEntityID().getValue());

    List<EntityStatement> statements = trustChain.getSuperiorStatements();
    String immediateSuperior = statements.get(0).getClaimsSet().getIssuer().getValue();
    claims.claim("authority_hints", List.of(immediateSuperior));

    Map<String, Object> rpMetadata = new HashMap<>();
    rpMetadata.put("client_id", registered.getClientId());
    rpMetadata.put("redirect_uris", registered.getRedirectUris());
    rpMetadata.put("token_endpoint_auth_method", registered.getTokenEndpointAuthMethod());
    rpMetadata.put("response_types",
        registered.getResponseTypes().stream().map(OAuthResponseType::getResponseType).toList());
    rpMetadata.put("grant_types",
        registered.getGrantTypes().stream().map(AuthorizationGrantType::getGrantType).toList());
    rpMetadata.put("scope", String.join(" ", registered.getScope()));
    rpMetadata.put("client_registration_types",
        trustChain.getLeafSelfStatement()
          .getClaimsSet()
          .getRPMetadata()
          .getClientRegistrationTypes()
          .stream()
          .map(ClientRegistrationType::toString)
          .toList());

    if (registered.getClientSecret() != null) {
      rpMetadata.put("client_secret", registered.getClientSecret());
    }

    claims.claim("metadata", Map.of("openid_relying_party", rpMetadata));

    JWSHeader header =
        new JWSHeader.Builder(alg).type(new JOSEObjectType("explicit-registration-response+jwt"))
          .keyID(signingKey.getKeyID())
          .build();

    SignedJWT jwt = new SignedJWT(header, claims.build());
    jwt.sign(signer);
    return jwt.serialize();
  }
}
