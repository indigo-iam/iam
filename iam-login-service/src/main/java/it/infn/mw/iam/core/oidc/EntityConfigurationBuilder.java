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
  private final List<String> authorityHints;
  private final String issuer;
  private final long expirationSec;
  private final Map<String, Object> metadata;

  public EntityConfigurationBuilder(JWKSetKeyStore keyStore,
      IamWellKnownInfoProvider wellKnownInfoProvider, OpenidFederationProperties fedProperties,
      IamProperties iamProperties) {
    signingKey = keyStore.getKeys()
      .stream()
      .filter(k -> k instanceof RSAKey && k.isPrivate())
      .map(k -> (RSAKey) k)
      .findFirst()
      .orElseThrow(() -> new IllegalStateException("No private RSA key found"));
    authorityHints = fedProperties.getEntityConfiguration().getAuthorityHints();
    if (iamProperties.getIssuer().endsWith("/")) {
      issuer = iamProperties.getIssuer();
    } else {
      issuer = iamProperties.getIssuer() + "/";
    }
    expirationSec = fedProperties.getEntityConfiguration().getExpirationSeconds();

    Map<String, Object> wellKnownInfo = wellKnownInfoProvider.getWellKnownInfo();
    if (authorityHints == null || authorityHints.isEmpty()) {
      throw new IllegalStateException("authority_hints must be present!");
    }

    Map<String, Object> opMetadata = new HashMap<>();
    opMetadata.put("issuer", wellKnownInfo.get("issuer"));
    opMetadata.put("authorization_endpoint", wellKnownInfo.get("authorization_endpoint"));
    opMetadata.put("jwks_uri", wellKnownInfo.get("jwks_uri"));
    opMetadata.put("response_types_supported", wellKnownInfo.get("response_types_supported"));
    opMetadata.put("subject_types_supported", wellKnownInfo.get("subject_types_supported"));
    opMetadata.put("id_token_signing_alg_values_supported",
        wellKnownInfo.get("id_token_signing_alg_values_supported"));
    opMetadata.put("client_registration_types_supported", List.of("explicit"));
    opMetadata.put("federation_registration_endpoint",
        URI.create(iamProperties.getBaseUrl()).resolve("/iam/api/oid-fed/client-registration"));

    Map<String, Object> feMetadata = new HashMap<>();
    String organizationName =
        fedProperties.getEntityConfiguration().getFederationEntity().getOrganizationName();
    List<String> contacts =
        fedProperties.getEntityConfiguration().getFederationEntity().getContacts();
    String logoUri = fedProperties.getEntityConfiguration().getFederationEntity().getLogoUri();
    if (organizationName != null && !organizationName.isBlank()) {
      feMetadata.put("organization_name", organizationName);
    }
    if (contacts != null && !contacts.isEmpty()) {
      feMetadata.put("contacts", contacts);
    }
    if (logoUri != null && !logoUri.isBlank()) {
      if (URI.create(logoUri).isAbsolute()) {
        feMetadata.put("logo_uri", logoUri);
      } else {
        throw new IllegalStateException("Logo URI must be absolute.");
      }
    }

    metadata = new HashMap<>();
    metadata.put("openid_provider", opMetadata);
    if (!feMetadata.isEmpty()) {
      metadata.put("federation_entity", feMetadata);
    }

    try {
      signer = JWKUtils.buildSigner(signingKey)
        .orElseThrow(() -> new IllegalStateException("Cannot build signer from key"));
    } catch (JOSEException e) {
      throw new IllegalStateException("Failed to build signer", e);
    }
  }

  public String build() throws JOSEException {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(issuer)
      .subject(issuer)
      .issueTime(new Date())
      .expirationTime(Date.from(Instant.now().plusSeconds(expirationSec)))
      .claim("jwks", signingKey.toPublicJWK().toJSONObject())
      .claim("metadata", metadata)
      .claim("authority_hints", authorityHints)
      .build();

    JWSHeader header = new JWSHeader.Builder(alg).keyID(signingKey.getKeyID())
      .type(new JOSEObjectType("entity-statement+jwt"))
      .build();

    SignedJWT jwt = new SignedJWT(header, claims);
    jwt.sign(signer);
    return jwt.serialize();
  }
}
