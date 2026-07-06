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
package it.infn.mw.iam.authn.oidc.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadata;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.core.oauth.discovery.DefaultOidcDiscoveryService;

@Service
public class OIDCProviderMetadataService {

  private final DefaultOidcDiscoveryService discoveryService;
  private final RestTemplate restTemplate;

  public OIDCProviderMetadataService(DefaultOidcDiscoveryService discoveryService,
      RestTemplateFactory restTemplateFactory) {
    this.discoveryService = discoveryService;
    this.restTemplate = restTemplateFactory.newRestTemplate();
  }

  public OIDCProviderMetadata load(String issuer) {

    JsonNode document = discoveryService.getDiscoveryDocument(issuer, restTemplate);

    return new OIDCProviderMetadata(document.get("issuer").asText(),
        document.get("authorization_endpoint").asText(), document.get("token_endpoint").asText(),
        document.get("jwks_uri").asText(), document.path("userinfo_endpoint").asText(null),
        document);
  }
}
