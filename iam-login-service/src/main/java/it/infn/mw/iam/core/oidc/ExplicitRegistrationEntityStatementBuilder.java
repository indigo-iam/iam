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
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.oidc.OpenidFederationProperties;
import it.infn.mw.iam.core.jwk.JWKUtils;
import it.infn.mw.iam.core.jwk.JwkKeyStore;
import it.infn.mw.iam.core.web.jwk.IamJWKSetPublishingEndpoint;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;

@Component
@Profile("openid-federation")
public class ExplicitRegistrationEntityStatementBuilder {

  private static final JWSAlgorithm alg = JWSAlgorithm.RS256;

  private final JWSSigner signer;
  private final RSAKey signingKey;
  private final Map<String, Object> jwks;
  private final String issuer;
  private final long expirationSec;
  private final Map<String, Object> metadata;
  private final Clock clock;

  public ExplicitRegistrationEntityStatementBuilder(JwkKeyStore keyStore,
      IamWellKnownInfoProvider wellKnownInfoProvider, OpenidFederationProperties fedProperties,
      IamProperties iamProperties, IamJWKSetPublishingEndpoint iamJwkEndpoint, Clock clock) {
    this.clock = clock;
    signingKey = keyStore.getKeys()
      .stream()
      .filter(k -> k instanceof RSAKey && k.isPrivate())
      .map(k -> (RSAKey) k)
      .findFirst()
      .orElseThrow(() -> new IllegalStateException("No private RSA key found"));
    String jsonKeys = iamJwkEndpoint.getJwk().getBody();
    try {
      jwks = JSONObjectUtils.parse(jsonKeys);
    } catch (ParseException e) {
      throw new IllegalArgumentException("Invalid JWK JSON");
    }
    if (iamProperties.getIssuer().endsWith("/")) {
      issuer = iamProperties.getIssuer();
    } else {
      issuer = iamProperties.getIssuer() + "/";
    }
    expirationSec = fedProperties.getEntityConfiguration().getExpirationSeconds();

    Map<String, Object> wellKnownInfo = wellKnownInfoProvider.getWellKnownInfo();
    metadata = new HashMap<>();
    metadata.put("openid_relying_party", buildRpMetadata(wellKnownInfo, iamProperties));

    try {
      signer = JWKUtils.buildSigner(signingKey)
        .orElseThrow(() -> new IllegalStateException("Cannot build signer from key"));
    } catch (JOSEException e) {
      throw new IllegalStateException("Failed to build signer", e);
    }
  }

  public String build(String opEntityId, List<String> authorityHints) throws JOSEException {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(issuer)
      .subject(issuer)
      .audience(opEntityId)
      .issueTime(Date.from(clock.instant()))
      .expirationTime(Date.from(Instant.now().plusSeconds(expirationSec)))
      .claim("jwks", jwks)
      .claim("authority_hints", authorityHints)
      .claim("metadata", Map.of("openid_relying_party", metadata))
      .build();

    JWSHeader header = new JWSHeader.Builder(alg).keyID(signingKey.getKeyID())
      .type(new JOSEObjectType("entity-statement+jwt"))
      .build();

    SignedJWT jwt = new SignedJWT(header, claims);
    jwt.sign(signer);
    return jwt.serialize();
  }

  private Map<String, Object> buildRpMetadata(Map<String, Object> wellKnownInfo,
      IamProperties iamProperties) {
    Map<String, Object> rpMetadata = new HashMap<>();
    rpMetadata.put("application_type", "web");
    rpMetadata.put("client_registration_types", List.of("explicit"));
    rpMetadata.put("redirect_uris",
        List.of(URI.create(iamProperties.getBaseUrl()).resolve("/openid_connect_login")));
    rpMetadata.put("jwks_uri", wellKnownInfo.get("jwks_uri"));
    return rpMetadata;
  }
}
