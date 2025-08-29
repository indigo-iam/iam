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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

@Service
public class TrustChainValidator {

  private final TrustAnchorRepository trustAnchorRepository;

  public TrustChainValidator(TrustAnchorRepository trustAnchorRepository) {
    this.trustAnchorRepository = trustAnchorRepository;
  }

  public TrustChain validate(List<EntityStatement> chain)
      throws InvalidTrustChainException, BadJOSEException, JOSEException {

    List<EntityStatement> cleanedChain = stripIntermediateECs(chain);

    for (EntityStatement es : cleanedChain) {
      validateClaims(es);
    }

    EntityStatement rpEC = cleanedChain.get(0);
    if (!rpEC.getClaimsSet().isSelfStatement()) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "Entity Configuration of RP must be self-issued (iss == sub)");
    }

    TrustChain trustChain;
    List<EntityStatement> withoutLeaf = cleanedChain.subList(1, cleanedChain.size());
    try {
      trustChain = new TrustChain(rpEC, withoutLeaf);
    } catch (IllegalArgumentException e) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "Invalid trust chain structure: " + e.getMessage(), e);
    }

    EntityID taId = trustChain.getTrustAnchorEntityID();
    if (!trustAnchorRepository.isTrusted(taId.getValue())) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "No trusted Trust Anchor found: " + taId.getValue());
    }

    EntityStatement ta = cleanedChain.get(cleanedChain.size() - 1);
    trustChain.verifySignatures(ta.getClaimsSet().getJWKSet());

    return trustChain;
  }

  private void validateClaims(EntityStatement es) throws InvalidTrustChainException {
    Date now = new Date();
    try {
      es.getClaimsSet().validateRequiredClaimsPresence();
    } catch (ParseException e) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "Missing or invalid required claims: " + e.getMessage(), e);
    }

    Date iat = es.getClaimsSet().getIssueTime();
    Date exp = es.getClaimsSet().getExpirationTime();

    if (iat.after(now)) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "Entity Statement has iat in the future: " + iat);
    }

    if (exp.before(now)) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "Entity Statement is expired: " + exp);
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
