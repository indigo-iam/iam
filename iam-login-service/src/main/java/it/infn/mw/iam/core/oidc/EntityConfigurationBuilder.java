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
import it.infn.mw.iam.core.web.wellknown.WellKnownConfiguration;

@Component
@Profile("openid-federation")
public class EntityConfigurationBuilder {

  private static final JWSAlgorithm alg = JWSAlgorithm.RS256;

  private final Clock clock;
  private final JWSSigner signer;
  private final RSAKey signingKey;
  private final Map<String, Object> jwks;
  private final List<String> authorityHints;
  private final String issuer;
  private final long expirationSec;
  private final Map<String, Object> metadata;

  public EntityConfigurationBuilder(Clock clock, JwkKeyStore keyStore,
      IamWellKnownInfoProvider wellKnownInfoProvider, OpenidFederationProperties fedProperties,
      IamProperties iamProperties, IamJWKSetPublishingEndpoint iamJwkEndpoint) {

    this.clock = clock;
    this.signingKey = keyStore.getKeys()
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
    authorityHints = fedProperties.getEntityConfiguration().getAuthorityHints();
    if (iamProperties.getIssuer().endsWith("/")) {
      issuer = iamProperties.getIssuer();
    } else {
      issuer = iamProperties.getIssuer() + "/";
    }
    expirationSec = fedProperties.getEntityConfiguration().getExpirationSeconds();

    if (authorityHints == null || authorityHints.isEmpty()) {
      throw new IllegalStateException("authority_hints must be present!");
    }

    WellKnownConfiguration wellKnownInfo = wellKnownInfoProvider.getWellKnownInfo();
    metadata = new HashMap<>();
    metadata.put("openid_provider", buildOpMetadata(wellKnownInfo, iamProperties));
    Map<String, Object> feMetadata = buildFeMetadata(fedProperties);
    if (!feMetadata.isEmpty()) {
      metadata.put("federation_entity", feMetadata);
    }
    metadata.put("openid_relying_party", buildRpMetadata(wellKnownInfo, iamProperties));

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
      .issueTime(Date.from(clock.instant()))
      .expirationTime(Date.from(Instant.now().plusSeconds(expirationSec)))
      .claim("jwks", jwks)
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

  private Map<String, Object> buildOpMetadata(WellKnownConfiguration wellKnownInfo,
      IamProperties iamProperties) {

    Map<String, Object> opMetadata = new HashMap<>();
    opMetadata.put("issuer", wellKnownInfo.issuer());
    opMetadata.put("authorization_endpoint", wellKnownInfo.authorizationEndpoint());
    opMetadata.put("jwks_uri", wellKnownInfo.jwksUri());
    opMetadata.put("response_types_supported", wellKnownInfo.responseTypesSupported());
    opMetadata.put("subject_types_supported", wellKnownInfo.subjectTypesSupported());
    opMetadata.put("id_token_signing_alg_values_supported",
        wellKnownInfo.idTokenSigningAlgValuesSupported());
    opMetadata.put("token_endpoint", wellKnownInfo.tokenEndpoint());
    opMetadata.put("userinfo_endpoint", wellKnownInfo.userinfoEndpoint());
    opMetadata.put("registration_endpoint", wellKnownInfo.registrationEndpoint());
    opMetadata.put("scopes_supported", wellKnownInfo.scopesSupported());
    opMetadata.put("claims_supported", wellKnownInfo.claimsSupported());
    opMetadata.put("client_registration_types_supported", List.of("explicit", "automatic"));
    opMetadata.put("federation_registration_endpoint",
        URI.create(iamProperties.getBaseUrl()).resolve("/iam/api/oid-fed/client-registration"));
    opMetadata.put("request_uri_parameter_supported", false);
    return opMetadata;
  }

  private Map<String, Object> buildFeMetadata(OpenidFederationProperties fedProperties) {
    Map<String, Object> feMetadata = new HashMap<>();
    var entity = fedProperties.getEntityConfiguration().getFederationEntity();

    String organizationName = entity.getOrganizationName();
    List<String> contacts = entity.getContacts();
    String logoUri = entity.getLogoUri();

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
    return feMetadata;
  }

  private Map<String, Object> buildRpMetadata(WellKnownConfiguration wellKnownInfo,
      IamProperties iamProperties) {
    Map<String, Object> rpMetadata = new HashMap<>();
    rpMetadata.put("application_type", "web");
    rpMetadata.put("client_registration_types", List.of("explicit"));
    rpMetadata.put("redirect_uris",
        List.of(URI.create(iamProperties.getBaseUrl()).resolve("/openid_connect_login")));
    rpMetadata.put("jwks_uri", wellKnownInfo.jwksUri());
    return rpMetadata;
  }
}
