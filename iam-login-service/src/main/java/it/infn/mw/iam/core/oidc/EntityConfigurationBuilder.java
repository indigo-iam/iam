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

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.mitre.jose.keystore.JWKSetKeyStore;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.config.oidc.OpenidFederationProperties;
import it.infn.mw.iam.core.jwk.JWKUtils;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;

@Component
@Profile("openid-federation")
public class EntityConfigurationBuilder {

  private final JWSSigner signer;
  private final RSAKey signingKey;
  private static final JWSAlgorithm alg = JWSAlgorithm.RS256;
  private final IamWellKnownInfoProvider wellKnownInfoProvider;
  private final OpenidFederationProperties openidFedProperties;

  public EntityConfigurationBuilder(JWKSetKeyStore keyStore,
      IamWellKnownInfoProvider wellKnownInfoProvider,
      OpenidFederationProperties openidFedProperties) {

    this.wellKnownInfoProvider = wellKnownInfoProvider;
    this.openidFedProperties = openidFedProperties;

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

  public String buildEntityConfiguration(String issuer, Map<String, Object> jwks)
      throws JOSEException {

    Map<String, Object> opMetadata = new HashMap<>(wellKnownInfoProvider.getWellKnownInfo());
    opMetadata.putIfAbsent("client_registration_types_supported", List.of("explicit"));
    Map<String, Object> metadata = Map.of("openid_provider", opMetadata);

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(issuer)
      .subject(issuer)
      .issueTime(new Date())
      .expirationTime(Date.from(Instant.now()
        .plusSeconds(openidFedProperties.getEntityConfiguration().getExpirationSeconds())))
      .claim("jwks", jwks)
      .claim("metadata", metadata)
      .claim("authority_hints", openidFedProperties.getEntityConfiguration().getAuthorityHints())
      .build();

    JWSHeader header = new JWSHeader.Builder(alg).keyID(signingKey.getKeyID())
      .type(new JOSEObjectType("entity-statement+jwt"))
      .build();

    SignedJWT jwt = new SignedJWT(header, claims);
    jwt.sign(signer);
    return jwt.serialize();
  }
}
