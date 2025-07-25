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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

@Service
public class TrustChainService {

  public static final Logger LOG = LoggerFactory.getLogger(TrustChainService.class);

  private final RestTemplate restTemplate;
  private final TrustAnchorRepository trustAnchorRepository;

  public TrustChainService(TrustAnchorRepository trustAnchorRepository) {
    this.restTemplate = new RestTemplate();
    this.trustAnchorRepository = trustAnchorRepository;
  }

  /**
   * Retrieve an already validated Trust Chain or attempt to resolve it
   * 
   * @throws JOSEException
   * @throws BadJOSEException
   */
  public Optional<TrustChain> getOrResolve(String entityId) throws BadJOSEException, JOSEException {
    try {
      TrustChain resolvedChain = resolveTrustChain(entityId);
      return Optional.of(resolvedChain);
    } catch (TrustChainException e) {
      return Optional.empty();
    }
  }

  /**
   * Resolve and validate a Trust Chain from the Entity Configuration of the RP
   * 
   * @throws JOSEException
   * @throws BadJOSEException
   */
  @Cacheable(cacheNames = "federationTrustChains", key = "#entityId")
  public TrustChain resolveTrustChain(String entityId)
      throws TrustChainException, BadJOSEException, JOSEException {
    // Retrieve RP Entity Configuration
    EntityStatement ec = fetchEntityConfiguration(entityId);

    // Recursive Trust Chain construction
    List<EntityStatement> chain = buildChain(ec, new HashSet<>());

    // Check that Trust Chain ends with a trusted TA
    EntityStatement ta = chain.get(chain.size() - 1);
    if (!trustAnchorRepository.isTrusted(ta.getEntityID().getValue())) {
      throw new TrustChainException("No trusted Trust Anchor found");
    }

    // Preliminary checks on claims and Trust Chain structure
    validateClaimsAndStructure(chain);

    // Cascading signatures (from TA to RP)
    validateSignatures(chain);

    return new TrustChain(ec, chain);
  }

  /**
   * Download Entity Configuration
   */
  private EntityStatement fetchEntityConfiguration(String entityId) throws TrustChainException {
    String url = entityId + "/.well-known/openid-federation";
    try {
      String jwt = restTemplate.getForObject(url, String.class);
      return EntityStatement.parse(jwt); // JWT decoding and parsing
    } catch (Exception e) {
      throw new TrustChainException("Failed to fetch EC: " + e.getMessage(), e);
    }
  }

  /**
   * Download Entity Statement
   */
  private EntityStatement fetchEntityStatement(String fetchEndpoint, String issuer, String subject)
      throws TrustChainException {
    try {
      String url = String.format("%s?sub=%s", fetchEndpoint,
          UriUtils.encode(subject, StandardCharsets.UTF_8));

      String jwt = restTemplate.getForObject(url, String.class);
      EntityStatement es = EntityStatement.parse(jwt);

      if (!issuer.equals(es.getClaimsSet().getIssuer().getValue())
          || !subject.equals(es.getClaimsSet().getSubject().getValue())) {
        throw new TrustChainException("Entity statement mismatch (iss/sub)");
      }
      return es;
    } catch (Exception e) {
      throw new TrustChainException(
          "Failed to fetch entity statement: " + issuer + " -> " + subject, e);
    }
  }

  /**
   * Recursively constructs the Trust Chain
   */
  private List<EntityStatement> buildChain(EntityStatement current, Set<String> seenEntityIds)
      throws TrustChainException {

    String currentId = current.getEntityID().getValue();

    if (seenEntityIds.contains(currentId)) {
      throw new TrustChainException("invalid_trust_chain: loop detected at " + currentId);
    }
    seenEntityIds.add(currentId);

    // If it is a Trust Anchor (self-signed) it ends the chain
    if (current.isTrustAnchor()) {
      return List.of(current);
    }

    List<EntityID> hints = current.getClaimsSet().getAuthorityHints();
    for (EntityID superior : hints) {
      try {
        // 1. Download EC of superior
        EntityStatement superiorEC = fetchEntityConfiguration(superior.getValue());

        // 2. Extract fetch_endpoint from the metadata
        String fetchEndpoint = superiorEC.getClaimsSet()
          .getFederationEntityMetadata()
          .getFederationAPIEndpointURI()
          .toASCIIString();

        if (fetchEndpoint == null) {
          throw new TrustChainException("No fetch_endpoint for " + superior.getValue());
        }

        // 3. Make the request fetch?sub=...
        EntityStatement es = fetchEntityStatement(fetchEndpoint, superior.getValue(), currentId);

        // 4. Recourse to the trust anchor
        List<EntityStatement> chain = buildChain(es, seenEntityIds);
        List<EntityStatement> fullChain = new ArrayList<>(chain);
        fullChain.add(0, current);
        return fullChain;

      } catch (TrustChainException e) {
        LOG.warn("Failed to resolve authority hint {} for entity {}: {}", superior.getValue(),
            current.getEntityID().getValue(), e.getMessage());
      }
    }
    throw new TrustChainException("No valid authority for: " + currentId);
  }

  private void validateClaims(EntityStatement es) throws TrustChainException {
    Date now = new Date();
    try {
      es.getClaimsSet().validateRequiredClaimsPresence();
    } catch (ParseException e) {
      throw new TrustChainException("Missing or invalid required claims: " + e.getMessage(), e);
    }

    // Check iat <= now && exp >= now
    Date iat = es.getClaimsSet().getIssueTime();
    Date exp = es.getClaimsSet().getExpirationTime();

    if (iat.after(now)) {
      throw new TrustChainException("Entity Statement has iat in the future: " + iat);
    }

    if (exp.before(now)) {
      throw new TrustChainException("Entity Statement is expired: " + exp);
    }
  }

  /**
   * Validation of all claims and issuer-subject consistency for the whole Trust Chain
   */
  private void validateClaimsAndStructure(List<EntityStatement> chain) throws TrustChainException {
    for (EntityStatement es : chain) {
      validateClaims(es);
    }

    // RP: iss == sub
    EntityStatement rpEC = chain.get(0);
    if (!rpEC.getClaimsSet().isSelfStatement()) {
      throw new TrustChainException(
          "Entity Configuration of RP must be self-issued self-issued (iss == sub)");
    }

    // TA: iss == sub
    EntityStatement trustAnchor = chain.get(chain.size() - 1);
    if (!trustAnchor.getClaimsSet().isSelfStatement()) {
      throw new TrustChainException(
          "Entity Configuration of Trust Anchor must be self-issued (iss == sub)");
    }

    // Iss-sub matching for each pair in the Trust Chain
    for (int i = 0; i < chain.size() - 1; i++) {
      EntityStatement current = chain.get(i);
      EntityStatement issuer = chain.get(i + 1);

      if (!current.getClaimsSet()
        .getIssuer()
        .getValue()
        .equals(issuer.getClaimsSet().getSubject().getValue())) {
        throw new TrustChainException("Issuer/Subject mismatch between chain elements");
      }
    }
  }

  /**
   * Check the signatures of the entire Trust Chain starting from the Trust Anchor
   * 
   * @throws JOSEException
   * @throws BadJOSEException
   */
  private void validateSignatures(List<EntityStatement> chain)
      throws TrustChainException, BadJOSEException, JOSEException {

    // Signature of the RP with its JWKS (self-signed)
    EntityStatement rpEC = chain.get(0);
    rpEC.verifySignatureOfSelfStatement();

    // Signature of the Trust Anchor with its JWKS (self-signed)
    EntityStatement trustAnchor = chain.get(chain.size() - 1);
    trustAnchor.verifySignatureOfSelfStatement();

    // Signing each ES with the public key of the next issuer
    for (int i = chain.size() - 2; i >= 0; i--) {
      EntityStatement current = chain.get(i);
      EntityStatement issuer = chain.get(i + 1);

      current.verifySignature(issuer.getClaimsSet().getJWKSet());
    }
  }
}
