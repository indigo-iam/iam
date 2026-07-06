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
package it.infn.mw.iam.test.ext_authn.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadata;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.service.OIDCProviderMetadataService;
import it.infn.mw.iam.core.oauth.discovery.DefaultOidcDiscoveryService;

@ExtendWith(MockitoExtension.class)
class OIDCProviderMetadataServiceTests {

  @Mock
  private DefaultOidcDiscoveryService discoveryService;

  @Mock
  private RestTemplateFactory restTemplateFactory;

  @Mock
  private RestTemplate restTemplate;


  @Test
  void testLoadMetadataSuccessfully() {

    ObjectMapper mapper = new ObjectMapper();

    ObjectNode doc = mapper.createObjectNode();
    doc.put("issuer", "https://issuer.example");
    doc.put("authorization_endpoint", "https://issuer.example/auth");
    doc.put("token_endpoint", "https://issuer.example/token");
    doc.put("jwks_uri", "https://issuer.example/jwks");
    doc.put("userinfo_endpoint", "https://issuer.example/userinfo");

    when(restTemplateFactory.newRestTemplate()).thenReturn(restTemplate);
    when(discoveryService.getDiscoveryDocument("https://issuer.example", restTemplate))
      .thenReturn(doc);

    OIDCProviderMetadataService service =
        new OIDCProviderMetadataService(discoveryService, restTemplateFactory);

    OIDCProviderMetadata metadata = service.load("https://issuer.example");

    assertEquals("https://issuer.example", metadata.issuer());
    assertEquals("https://issuer.example/auth", metadata.authorizationEndpoint());
    assertEquals("https://issuer.example/token", metadata.tokenEndpoint());
    assertEquals("https://issuer.example/jwks", metadata.jwksUri());
    assertEquals("https://issuer.example/userinfo", metadata.userInfoEndpoint());
  }


}
