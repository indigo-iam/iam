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
package it.infn.mw.iam.test.oauth.introspection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.core.oauth.discovery.DefaultOidcDiscoveryService;
import it.infn.mw.iam.core.oauth.discovery.OidcDiscoveryService;

@ExtendWith(MockitoExtension.class)
class OidcDiscoveryServiceTests {

  OidcDiscoveryService discoveryService = new DefaultOidcDiscoveryService();

  @Mock
  RestTemplate restTemplate;

  @Test
  void testRestClientException() {
    Mockito.when(restTemplate.getForEntity(Mockito.anyString(), Mockito.eq(JsonNode.class)))
      .thenThrow(new RuntimeException("Error"));

    RestClientException e = assertThrows(RestClientException.class,
        () -> discoveryService.getDiscoveryDocument("https://test.example", restTemplate));
    assertEquals("Unable to discover OpenID configuration for issuer https://test.example",
        e.getMessage());
  }

  @Test
  void testSuccessfulOidcDiscovery() {

    JsonNode jsonNode = new ObjectMapper().createObjectNode().put("issuer", "https://test.example");

    Mockito
      .when(restTemplate.getForEntity("https://test.example/.well-known/openid-configuration",
          JsonNode.class))
      .thenReturn(ResponseEntity.ok(jsonNode));

    var result = discoveryService.getDiscoveryDocument("https://test.example", restTemplate);

    assertEquals("https://test.example", result.get("issuer").asText());
  }

  @Test
  void testFallbackToSecondDiscoveryEndpoint() {

    JsonNode jsonNode = new ObjectMapper().createObjectNode().put("issuer", "https://test.example");

    Mockito
      .when(restTemplate.getForEntity("https://test.example/.well-known/openid-configuration",
          JsonNode.class))
      .thenThrow(new RestClientException("First endpoint failed"));

    Mockito
      .when(restTemplate.getForEntity("https://test.example/.well-known/oauth-authorization-server",
          JsonNode.class))
      .thenReturn(ResponseEntity.ok(jsonNode));

    var result = discoveryService.getDiscoveryDocument("https://test.example", restTemplate);

    assertEquals("https://test.example", result.get("issuer").asText());
  }

  @Test
  void testIssuerWithTrailingSlash() {

    JsonNode jsonNode = new ObjectMapper().createObjectNode().put("issuer", "https://test.example");

    Mockito.when(restTemplate.getForEntity("https://test.example/.well-known/openid-configuration", JsonNode.class))
      .thenReturn(ResponseEntity.ok(jsonNode));

    var result = discoveryService.getDiscoveryDocument("https://test.example/", restTemplate);

    assertEquals("https://test.example", result.get("issuer").asText());
  }

}
