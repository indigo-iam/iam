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

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.oidc.OpenidFederationProperties;
import it.infn.mw.iam.core.jwk.JWKUtils;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;

@Component
@Profile("openid-federation")
public class EntityConfigurationBuilder {

  private static final JWSAlgorithm alg = JWSAlgorithm.RS256;

  private final JWSSigner signer;
  private final RSAKey signingKey;
  private final IamWellKnownInfoProvider wellKnownInfoProvider;
  private final OpenidFederationProperties openidFedProperties;
  private final IamProperties iamProperties;

  public EntityConfigurationBuilder(JWKSetKeyStore keyStore,
      IamWellKnownInfoProvider wellKnownInfoProvider,
      OpenidFederationProperties openidFedProperties, IamProperties iamProperties) {
    this.wellKnownInfoProvider = wellKnownInfoProvider;
    this.openidFedProperties = openidFedProperties;
    this.iamProperties = iamProperties;
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

  public String buildEntityConfiguration(Map<String, Object> jwks) throws JOSEException {
    String issuer = iamProperties.getIssuer();

    Map<String, Object> opMetadata = new HashMap<>(wellKnownInfoProvider.getWellKnownInfo());
    opMetadata.putIfAbsent("client_registration_types_supported", List.of("explicit"));
    opMetadata.put("federation_registration_endpoint",
        URI.create(issuer).resolve("/iam/openid-federation/client-registration"));

    Map<String, Object> feMetadata = new HashMap<>();
    feMetadata.put("contacts", List.of("iam-support@lists.infn.it"));
    feMetadata.put("organization_name", iamProperties.getOrganisation().getName());
    feMetadata.put("logo_uri", iamProperties.getLogo().getUrl());

    Map<String, Object> metadata = new HashMap<>();
    metadata.put("openid_provider", opMetadata);
    metadata.put("federation_entity", feMetadata);

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
