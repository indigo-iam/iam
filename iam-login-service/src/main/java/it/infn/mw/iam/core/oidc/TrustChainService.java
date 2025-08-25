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
import java.util.Comparator;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.config.TrustChainCache;

@Service
@Profile("openid-federation")
public class TrustChainService {

  public static final Logger LOG = LoggerFactory.getLogger(TrustChainService.class);

  private final RestTemplate restTemplate;
  private final TrustAnchorRepository trustAnchorRepository;
  private final TrustChainCache trustChainCache;

  public TrustChainService(TrustAnchorRepository trustAnchorRepository,
      TrustChainCache trustChainCache) {
    this.restTemplate = new RestTemplate();
    this.trustAnchorRepository = trustAnchorRepository;
    this.trustChainCache = trustChainCache;
  }

  /**
   * Retrieve an already validated Trust Chain or attempt to resolve it
   * 
   * @throws JOSEException
   * @throws BadJOSEException
   */
  public Optional<TrustChain> getOrResolve(String entityId) throws BadJOSEException, JOSEException {
    Optional<TrustChain> cachedChain = trustChainCache.get(entityId);
    if (!cachedChain.isEmpty()) {
      return cachedChain;
    }
    try {
      TrustChain resolvedChain = resolveTrustChain(entityId);
      trustChainCache.put(entityId, resolvedChain);
      return Optional.of(resolvedChain);
    } catch (InvalidTrustChainException e) {
      return Optional.empty();
    }
  }

  /**
   * Resolve and validate a Trust Chain from the Entity Configuration of the RP
   * 
   * @throws JOSEException
   * @throws BadJOSEException
   */
  public TrustChain resolveTrustChain(String entityId)
      throws InvalidTrustChainException, BadJOSEException, JOSEException {
    // Retrieve RP Entity Configuration
    EntityStatement ec = fetchEntityConfiguration(entityId);

    // Recursive Trust Chain construction
    List<EntityStatement> chain = buildChain(ec, new HashSet<>());

    // Clean EC of intermediate entities
    List<EntityStatement> cleanedChain = stripIntermediateECs(chain);

    // Validate base claims
    for (EntityStatement es : cleanedChain) {
      validateClaims(es);
    }

    // RP: check iss == sub
    EntityStatement rpEC = cleanedChain.get(0);
    if (!rpEC.getClaimsSet().isSelfStatement()) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "Entity Configuration of RP must be self-issued (iss == sub)");
    }

    // Build TrustChain (check iss/sub chain)
    TrustChain trustChain;
    List<EntityStatement> withoutLeaf = cleanedChain.subList(1, cleanedChain.size());
    try {
      trustChain = new TrustChain(ec, withoutLeaf);
    } catch (IllegalArgumentException e) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "Invalid trust chain structure: " + e.getMessage(), e);
    }

    // Check that Trust Chain ends with a trusted TA
    EntityID taId = trustChain.getTrustAnchorEntityID();
    if (!trustAnchorRepository.isTrusted(taId.getValue())) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "No trusted Trust Anchor found: " + taId.getValue());
    }

    // Cascading signatures (from TA to RP)
    EntityStatement ta = cleanedChain.get(cleanedChain.size() - 1);
    trustChain.verifySignatures(ta.getClaimsSet().getJWKSet());

    return trustChain;
  }

  /**
   * Download Entity Configuration
   */
  private EntityStatement fetchEntityConfiguration(String entityId) throws InvalidTrustChainException {
    String url = entityId + "/.well-known/openid-federation";
    try {
      String jwt = restTemplate.getForObject(url, String.class);
      return EntityStatement.parse(jwt); // JWT decoding and parsing
    } catch (Exception e) {
      throw new InvalidTrustChainException("invalid_trust_chain", "Failed to fetch EC: " + e.getMessage(),
          e);
    }
  }

  /**
   * Download Entity Statement
   */
  private EntityStatement fetchEntityStatement(String fetchEndpoint, String issuer, String subject)
      throws InvalidTrustChainException {
    try {
      String url = String.format("%s?sub=%s", fetchEndpoint,
          UriUtils.encode(subject, StandardCharsets.UTF_8));

      String jwt = restTemplate.getForObject(url, String.class);
      EntityStatement es = EntityStatement.parse(jwt);

      if (!issuer.equals(es.getClaimsSet().getIssuer().getValue())
          || !subject.equals(es.getClaimsSet().getSubject().getValue())) {
        throw new InvalidTrustChainException("invalid_trust_chain", "Entity statement mismatch (iss/sub)");
      }
      return es;
    } catch (Exception e) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "Failed to fetch entity statement: " + issuer + " -> " + subject, e);
    }
  }

  /**
   * Recursively constructs the Trust Chain
   */
  private List<EntityStatement> buildChain(EntityStatement current, Set<String> seenEntityIds)
      throws InvalidTrustChainException {

    String currentId = current.getEntityID().getValue();

    if (seenEntityIds.contains(currentId)) {
      throw new InvalidTrustChainException("invalid_trust_chain", "Loop detected at " + currentId);
    }
    seenEntityIds.add(currentId);

    // If it is a Trust Anchor (self-signed) it ends the chain
    if (current.isTrustAnchor()) {
      return List.of(current);
    }

    List<List<EntityStatement>> candidateChains = new ArrayList<>();

    for (EntityID superior : current.getClaimsSet().getAuthorityHints()) {
      try {
        // 1. Download EC of superior
        EntityStatement superiorEC = fetchEntityConfiguration(superior.getValue());

        // 2. Extract fetch_endpoint from the metadata
        var fedMeta = superiorEC.getClaimsSet().getFederationEntityMetadata();
        if (fedMeta == null || fedMeta.getFederationAPIEndpointURI() == null) {
          throw new InvalidTrustChainException("invalid_trust_chain",
              "No fetch_endpoint for " + superior.getValue());
        }
        String fetchEndpoint = fedMeta.getFederationAPIEndpointURI().toASCIIString();

        // 3. Make the request fetch?sub=...
        EntityStatement es = fetchEntityStatement(fetchEndpoint, superior.getValue(), currentId);

        // 4. Recourse to the trust anchor
        List<EntityStatement> upperChain = buildChain(superiorEC, seenEntityIds);
        List<EntityStatement> fullChain = new ArrayList<>();
        fullChain.add(current);
        fullChain.add(es);
        fullChain.addAll(upperChain);
        candidateChains.add(fullChain);

      } catch (InvalidTrustChainException e) {
        LOG.warn("Failed to resolve authority hint {} for entity {}: {}", superior.getValue(),
            current.getEntityID().getValue(), e.getMessage());
      }
    }
    return candidateChains.stream()
      .min(Comparator.comparingInt(List::size)) // a shorter chain is preferred
      .orElseThrow(() -> new InvalidTrustChainException("invalid_trust_chain",
          "No valid authority for: " + currentId));
  }

  private void validateClaims(EntityStatement es) throws InvalidTrustChainException {
    Date now = new Date();
    try {
      es.getClaimsSet().validateRequiredClaimsPresence();
    } catch (ParseException e) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "Missing or invalid required claims: " + e.getMessage(), e);
    }

    // Check iat <= now && exp >= now
    Date iat = es.getClaimsSet().getIssueTime();
    Date exp = es.getClaimsSet().getExpirationTime();

    if (iat.after(now)) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "Entity Statement has iat in the future: " + iat);
    }

    if (exp.before(now)) {
      throw new InvalidTrustChainException("invalid_trust_chain", "Entity Statement is expired: " + exp);
    }
  }

  private List<EntityStatement> stripIntermediateECs(List<EntityStatement> chain) {
    if (chain.isEmpty()) {
      return chain;
    }

    List<EntityStatement> cleaned = new ArrayList<>();

    // Leaf EC
    if (chain.get(0).getClaimsSet().isSelfStatement()) {
      cleaned.add(chain.get(0));
    }

    // ES only (skip intermediates ECs)
    chain.subList(1, chain.size() - 1)
      .stream()
      .filter(es -> !es.getClaimsSet().isSelfStatement())
      .forEach(cleaned::add);

    // TA EC
    EntityStatement last = chain.get(chain.size() - 1);
    if (last.isTrustAnchor()) {
      cleaned.add(last);
    }

    return cleaned;
  }
}
