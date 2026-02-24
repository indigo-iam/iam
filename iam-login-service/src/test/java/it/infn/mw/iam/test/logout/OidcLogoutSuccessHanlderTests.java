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
package it.infn.mw.iam.test.logout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.Base64;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.jwt.assertion.impl.SelfAssertionValidator;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.authn.OidcLogoutSuccessHandler;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@ExtendWith(MockitoExtension.class)
public class OidcLogoutSuccessHanlderTests {

  @Mock
  private IamClientRepository clientRepo;

  @Mock
  private SelfAssertionValidator validator;

  private OidcLogoutSuccessHandler handler;

  private MockHttpServletRequest request;
  private MockHttpServletResponse response;

  @BeforeEach
  void setup() {
    handler = new OidcLogoutSuccessHandler(clientRepo, validator);
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
  }

  private void mockClient(String clientId, Set<String> redirectUris) {
    ClientDetailsEntity client = new ClientDetailsEntity();
    client.setClientId(clientId);
    client.setPostLogoutRedirectUris(redirectUris);

    when(clientRepo.findByClientId(clientId)).thenReturn(Optional.of(client));
  }

  private String validJwtForClient(String clientId) {
    return "eyJhbGciOiJub25lIn0." + Base64.getUrlEncoder()
      .withoutPadding()
      .encodeToString(("{\"aud\":[\"" + clientId + "\"]}").getBytes()) + ".";
  }

  @Test
  void missingParametersRedirectsToFallback() throws Exception {
    handler.onLogoutSuccess(request, response, null);

    assertEquals("/login?logout", response.getRedirectedUrl());
  }

  @Test
  void invalidIdTokenRedirectsToFallback() throws Exception {
    request.setParameter("id_token_hint", "not-a-jwt");
    request.setParameter("post_logout_redirect_uri", "https://rp.example.org");

    handler.onLogoutSuccess(request, response, null);

    assertEquals("/login?logout", response.getRedirectedUrl());
  }

  @Test
  void tokenValidationFailsRedirectsToFallback() throws Exception {
    String jwt = "eyJhbGciOiJub25lIn0.eyJhdWQiOlsiY2xpZW50Il19.";

    request.setParameter("id_token_hint", jwt);
    request.setParameter("post_logout_redirect_uri", "https://rp.example.org");

    when(validator.isValid(any(JWT.class))).thenReturn(false);

    handler.onLogoutSuccess(request, response, null);

    assertEquals("/login?logout", response.getRedirectedUrl());
  }

  @Test
  void redirectUriNotRegisteredRedirectsToFallback() throws Exception {
    String jwt = validJwtForClient("client");

    request.setParameter("id_token_hint", jwt);
    request.setParameter("post_logout_redirect_uri", "https://evil.example.org");

    when(validator.isValid(any(JWT.class))).thenReturn(true);
    mockClient("client", Set.of("https://rp.example.org/logout"));

    handler.onLogoutSuccess(request, response, null);

    assertEquals("/login?logout", response.getRedirectedUrl());
  }

  @Test
  void validLogoutRedirectsToPostLogoutUri() throws Exception {
    String jwt = validJwtForClient("client");

    request.setParameter("id_token_hint", jwt);
    request.setParameter("post_logout_redirect_uri", "https://rp.example.org/logout");
    request.setParameter("state", "xyz");

    when(validator.isValid(any(JWT.class))).thenReturn(true);
    mockClient("client", Set.of("https://rp.example.org/logout"));

    handler.onLogoutSuccess(request, response, null);

    assertEquals("https://rp.example.org/logout?state=xyz", response.getRedirectedUrl());
  }
}
