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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;

@Service
public class TrustChainResolver {

  public static final Logger LOG = LoggerFactory.getLogger(TrustChainResolver.class);
  private final RestTemplate restTemplate = new RestTemplate();

  private EntityStatement fetchEntityConfiguration(String entityId)
      throws InvalidTrustChainException {
    String url = entityId + (entityId.endsWith("/") ? "" : "/") + ".well-known/openid-federation";
    try {
      String jwt = restTemplate.getForObject(url, String.class);
      return EntityStatement.parse(jwt);
    } catch (Exception e) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "Failed to fetch EC: " + e.getMessage(), e);
    }
  }

  private EntityStatement fetchEntityStatement(String fetchEndpoint, String issuer, String subject)
      throws InvalidTrustChainException {
    try {
      String url = String.format("%s?sub=%s", fetchEndpoint,
          UriUtils.encode(subject, StandardCharsets.UTF_8));

      String jwt = restTemplate.getForObject(url, String.class);
      EntityStatement es = EntityStatement.parse(jwt);

      if (!issuer.equals(es.getClaimsSet().getIssuer().getValue())
          || !subject.equals(es.getClaimsSet().getSubject().getValue())) {
        throw new InvalidTrustChainException("invalid_trust_chain",
            "Entity statement mismatch (iss/sub)");
      }
      return es;
    } catch (Exception e) {
      throw new InvalidTrustChainException("invalid_trust_chain",
          "Failed to fetch entity statement: " + issuer + " -> " + subject, e);
    }
  }

  /**
   * Resolve the Trust Chain starting from an entity_id
   */
  public List<List<EntityStatement>> resolveFromEntityId(String entityId)
      throws InvalidTrustChainException {
    EntityStatement ec = fetchEntityConfiguration(entityId);
    return buildChain(ec, new HashSet<>());
  }

  /**
   * Resolve the Trust Chain starting from an EntityConfiguration already provided
   */
  public List<List<EntityStatement>> resolveFromEntityConfiguration(EntityStatement ec)
      throws InvalidTrustChainException {
    return buildChain(ec, new HashSet<>());
  }

  /**
   * Recursion to build the Trust Chain up to a Trust Anchor
   */
  private List<List<EntityStatement>> buildChain(EntityStatement subordinateEC,
      Set<String> seenEntityIds) throws InvalidTrustChainException {

    String subId = subordinateEC.getEntityID().getValue();

    if (!seenEntityIds.add(subId)) {
      throw new InvalidTrustChainException("invalid_trust_chain", "Loop detected at " + subId);
    }

    // If it is a Trust Anchor (self-signed) it ends the chain
    if (subordinateEC.isTrustAnchor()) {
      List<List<EntityStatement>> chain = new ArrayList<>();
      chain.add(List.of(subordinateEC));
      return chain;
    }

    List<List<EntityStatement>> chains = new ArrayList<>();
    int invalidChains = 0;

    for (EntityID superior : subordinateEC.getClaimsSet().getAuthorityHints()) {
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
        EntityStatement subordinateES =
            fetchEntityStatement(fetchEndpoint, superior.getValue(), subId);

        // 4. Recourse to the trust anchor
        List<List<EntityStatement>> forwardChains =
            buildChain(superiorEC, new HashSet<>(seenEntityIds));

        for (List<EntityStatement> chain : forwardChains) {
          List<EntityStatement> newChain = new ArrayList<>();
          newChain.add(subordinateEC);
          newChain.add(subordinateES);
          newChain.addAll(chain);
          chains.add(newChain);
        }
      } catch (InvalidTrustChainException e) {
        invalidChains++;
        LOG.warn("Failed to resolve authority {} for entity {}: {}", superior.getValue(), subId,
            e.getMessage());
      }
    }

    if (invalidChains == subordinateEC.getClaimsSet().getAuthorityHints().size()) {
      throw new InvalidTrustChainException("invalid_trust_chain", "No valid chains for " + subId);
    }

    return chains;
  }
}
