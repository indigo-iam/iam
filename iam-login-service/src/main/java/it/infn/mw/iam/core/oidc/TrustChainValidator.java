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

import static it.infn.mw.iam.core.oidc.FederationException.invalidTrustChain;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

@Service
@Profile("openid-federation")
public class TrustChainValidator {

  public static final Logger LOG = LoggerFactory.getLogger(TrustChainValidator.class);

  private final Clock clock;
  private final TrustAnchorRepository trustAnchorRepository;

  public TrustChainValidator(Clock clock, TrustAnchorRepository trustAnchorRepository) {
    this.clock = clock;
    this.trustAnchorRepository = trustAnchorRepository;
  }

  /**
   * Validate all chains and select the shortest among the valid ones
   */
  public TrustChain validateAll(List<List<EntityStatement>> chains) throws FederationException {

    if (chains == null || chains.isEmpty()) {
      throw invalidTrustChain("No chains provided");
    }

    List<TrustChain> validChains = new ArrayList<>();

    for (List<EntityStatement> chain : chains) {
      try {
        TrustChain tc = validate(chain);
        validChains.add(tc);
      } catch (FederationException e) {
        LOG.warn("Invalid chain discarded: {}", e.getMessage());
      }
    }

    if (validChains.isEmpty()) {
      throw invalidTrustChain("No valid trust chains found");
    }

    // Choose the TrustChain with fewer steps
    return validChains.stream()
      .min(Comparator.comparingInt(tc -> tc.getSuperiorStatements().size()))
      .orElseThrow(() -> invalidTrustChain("Unexpected selection failure"));
  }

  /**
   * Validate a single chain of EntityStatements
   */
  public TrustChain validate(List<EntityStatement> chain) throws FederationException {

    List<EntityStatement> cleanedChain = stripIntermediateECs(chain);

    for (EntityStatement es : cleanedChain) {
      validateClaims(es);
    }

    // RP Entity Configuration must be self-issued
    EntityStatement rpEC = cleanedChain.get(0);
    if (!rpEC.getClaimsSet().isSelfStatement()) {
      throw invalidTrustChain("Entity Configuration of RP must be self-issued (iss == sub)");
    }

    // Build a TrustChain without leaf
    List<EntityStatement> withoutLeaf = cleanedChain.subList(1, cleanedChain.size());
    TrustChain trustChain;
    try {
      trustChain = new TrustChain(rpEC, withoutLeaf);
    } catch (IllegalArgumentException e) {
      throw invalidTrustChain("Invalid trust chain structure: " + e.getMessage(), e);
    }

    // Verify the Trust Anchor is known
    EntityID taId = trustChain.getTrustAnchorEntityID();
    if (!trustAnchorRepository.isTrusted(taId.getValue())) {
      throw invalidTrustChain("No trusted Trust Anchor found: " + taId.getValue());
    }

    // Verify signatures using TA public key
    EntityStatement ta = cleanedChain.get(cleanedChain.size() - 1);
    try {
      trustChain.verifySignatures(ta.getClaimsSet().getJWKSet());
    } catch (BadJOSEException | JOSEException e) {
      throw invalidTrustChain("Invalid signature: " + e.getMessage(), e);
    }

    return trustChain;
  }

  private void validateClaims(EntityStatement es) throws FederationException {

    Date now = Date.from(clock.instant());
    try {
      es.getClaimsSet().validateRequiredClaimsPresence();
    } catch (ParseException e) {
      throw invalidTrustChain("Missing or invalid required claims: " + e.getMessage(), e);
    }

    Date iat = es.getClaimsSet().getIssueTime();
    Date exp = es.getClaimsSet().getExpirationTime();

    if (iat.after(now)) {
      throw invalidTrustChain("Entity Statement has iat in the future: " + iat);
    }

    if (exp.before(now)) {
      throw invalidTrustChain("Entity Statement is expired: " + exp);
    }
  }

  private List<EntityStatement> stripIntermediateECs(List<EntityStatement> chain) {
    if (chain.isEmpty())
      return chain;

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
