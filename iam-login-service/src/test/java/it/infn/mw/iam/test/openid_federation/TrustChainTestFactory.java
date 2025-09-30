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
package it.infn.mw.iam.test.openid_federation;

import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.entities.FederationEntityMetadata;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

public class TrustChainTestFactory {

  private static final Map<String, RSAKey> KEYS = new HashMap<>();

  private static RSAKey keyFor(String entity) {
    return KEYS.computeIfAbsent(entity, id -> {
      try {
        return new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
      } catch (JOSEException e) {
        throw new RuntimeException(e);
      }
    });
  }

  // self-issued EC: iss == sub, jwks = own key
  public static EntityStatement selfEC(String entity, Date iat, Date exp,
      List<EntityID> authorityHints, URI fetchEndpoint, OIDCClientMetadata metadata,
      String audience) throws JOSEException {
    RSAKey key = keyFor(entity);
    EntityID eid = new EntityID(entity);

    EntityStatementClaimsSet claims =
        new EntityStatementClaimsSet(eid, eid, iat, exp, new JWKSet(key.toPublicJWK()));

    if (metadata != null) {
      claims.setRPMetadata(metadata);
    }
    if (fetchEndpoint != null) {
      claims.setFederationEntityMetadata(new FederationEntityMetadata(fetchEndpoint));
    }
    if (authorityHints != null && !authorityHints.isEmpty()) {
      claims.setAuthorityHints(authorityHints);
    }
    if (audience != null) {
      claims.setAudience(Audience.create(List.of(audience)));
    }
    return EntityStatement.sign(claims, key);
  }

  // superior ES: signed by iss, jwks = key of the Trust Chain sub
  public static EntityStatement superiorES(String issuer, String subject, Date iat, Date exp)
      throws JOSEException {
    RSAKey issuerKey = keyFor(issuer);
    RSAKey subjectKey = keyFor(subject);

    EntityStatementClaimsSet claims = new EntityStatementClaimsSet(new EntityID(issuer),
        new EntityID(subject), iat, exp, new JWKSet(subjectKey.toPublicJWK()));

    return EntityStatement.sign(claims, issuerKey);
  }

  /** Minimum Trust Chain: RP → TA */
  public static TrustChain createRpToTaChain(String aud) throws JOSEException {
    Date now = new Date();
    Date exp = new Date(now.getTime() + 600000);

    String rp = "https://rp.example";
    String ta = "https://ta.example";

    // RP self EC with authority_hint = TA
    OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
    clientMetadata.setRedirectionURI(URI.create(rp + "/callback"));
    clientMetadata.setName("Relying Party");
    clientMetadata.setClientRegistrationTypes(List.of(ClientRegistrationType.EXPLICIT));
    EntityStatement rpEC =
        selfEC(rp, now, exp, List.of(new EntityID(ta)), null, clientMetadata, aud);

    // TA → RP ES
    EntityStatement taToRp = superiorES(ta, rp, now, exp);

    // Build the TrustChain
    return new TrustChain(rpEC, List.of(taToRp));
  }

  /** Trust Chain: RP → Intermediate → TA */
  public static TrustChain createRpToIntermediateToTaChain(String ta) throws JOSEException {
    Date now = new Date();
    Date exp = new Date(now.getTime() + 600000);

    String rp = "https://rp.example";
    String ia = "https://intermediate.example";

    // RP self EC with authority_hint = Intermediate
    OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
    clientMetadata.setRedirectionURI(URI.create(rp + "/callback"));
    EntityStatement rpEC =
        selfEC(rp, now, exp, List.of(new EntityID(ia)), null, clientMetadata, null);

    // Intermediate → RP ES
    EntityStatement intermToRp = superiorES(ia, rp, now, exp);

    // TA → Intermediate ES
    EntityStatement taToInterm = superiorES(ta, ia, now, exp);

    // Build the TrustChain: RP EC, intermediate → RP, TA → intermediate
    return new TrustChain(rpEC, List.of(intermToRp, taToInterm));
  }
}
