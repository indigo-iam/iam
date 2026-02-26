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
package it.infn.mw.iam.core.oauth.discovery;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class DefaultOidcDiscoveryService implements OidcDiscoveryService {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultOidcDiscoveryService.class);


  private static final List<String> DISCOVERY_URLS =
      List.of("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server");

  @Override
  public JsonNode getDiscoveryDocument(String issuer, RestTemplate restTemplate)
      throws RestClientException {

    String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;

    LOG.info("Discovering OIDC configuration for issuer: {}", issuer);

    for (String url : DISCOVERY_URLS) {
      try {
        ResponseEntity<JsonNode> resp = restTemplate.getForEntity(base + url, JsonNode.class);
        LOG.info("Discover response status code: {}", resp.getStatusCode());
        
        if (resp.getStatusCode().is2xxSuccessful() && resp.getBody() != null) {
          LOG.debug("Discover response body: {}", resp.getBody());
          return resp.getBody();
        }
      } catch (Throwable e) {
        LOG.error("Error fetching discovery document from {} for issuer {}: {}", url, issuer,
            e.getMessage());
      }
    }

    throw new RestClientException("Unable to discover OpenID configuration for issuer " + issuer);
  }

}
