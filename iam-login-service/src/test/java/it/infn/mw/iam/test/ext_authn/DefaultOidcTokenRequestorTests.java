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
package it.infn.mw.iam.test.ext_authn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.authn.oidc.DefaultOidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.OidcClientError;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.model.TokenEndpointErrorResponse;
import it.infn.mw.iam.config.oidc.OidcClient;

@ExtendWith(MockitoExtension.class)
class DefaultOidcTokenRequestorTests {

  @Mock
  private RestTemplateFactory restTemplateFactory;

  @Mock
  private RestTemplate restTemplate;

  @Mock
  private ObjectMapper mapper;

  private DefaultOidcTokenRequestor requestor;

  private static final String ISSUER = "https://test.example";

  @BeforeEach
  void setUp() {
    when(restTemplateFactory.newRestTemplate()).thenReturn(restTemplate);
    requestor = new DefaultOidcTokenRequestor(restTemplateFactory, mapper);
  }

  @Test
  void testPrepareTokenRequestWithSecretPostAuthMethod() throws JsonProcessingException {

    OidcClient client = new OidcClient("client", "secret", ISSUER + "/openid_connect_login", null,
        null, null, AuthMethod.SECRET_POST);

    Map<String, String> mockResponse = Map.of("access_token", "token");
    String jsonResponse = mapper.writeValueAsString(mockResponse);

    when(restTemplate.postForObject(anyString(), any(HttpEntity.class), eq(String.class)))
      .thenReturn(jsonResponse);

    String response =
        requestor.requestTokens(ISSUER + "/token", client, new LinkedMultiValueMap<>());

    assertEquals(jsonResponse, response);

    client = new OidcClient("client", "secret", ISSUER + "/openid_connect_login", null, null, null,
        AuthMethod.NONE);
    when(restTemplate.postForObject(anyString(), any(HttpEntity.class), eq(String.class)))
      .thenReturn(jsonResponse);

    response = requestor.requestTokens(ISSUER + "/token", client, new LinkedMultiValueMap<>());

    assertEquals(jsonResponse, response);
  }

  @Test
  void testRequestTokensThrowsOidcClientErrorOnRestClientException() {

    OidcClient client = new OidcClient("client", "secret", ISSUER + "/openid_connect_login", null,
        null, null, AuthMethod.NONE);

    when(restTemplate.postForObject(anyString(), any(HttpEntity.class), eq(String.class)))
      .thenThrow(new RestClientException("connection refused"));

    OidcClientError ex = assertThrows(OidcClientError.class,
        () -> requestor.requestTokens(ISSUER + "/token", client, new LinkedMultiValueMap<>()));

    assertEquals("Token request error: connection refused", ex.getMessage());
  }

  @Test
  void testRequestTokensWithBadRequestAndInvalidJsonResponse()
      throws StreamReadException, DatabindException, IOException {

    OidcClient client = new OidcClient("client", "secret", ISSUER + "/openid_connect_login", null,
        null, null, AuthMethod.NONE);

    HttpClientErrorException exception =
        HttpClientErrorException.create(HttpStatus.BAD_REQUEST, "Bad request", HttpHeaders.EMPTY,
            "invalid json".getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);

    when(restTemplate.postForObject(anyString(), any(HttpEntity.class), eq(String.class)))
      .thenThrow(exception);


    when(mapper.readValue(any(byte[].class), eq(TokenEndpointErrorResponse.class)))
      .thenThrow(new IOException("cannot parse"));

    OidcClientError ex = assertThrows(OidcClientError.class,
        () -> requestor.requestTokens(ISSUER + "/token", client, new LinkedMultiValueMap<>()));

    assertTrue(ex.getMessage().contains("Token request error"));
  }
}
