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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.web.client.RestClientException;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;

@AutoConfigureMockMvc
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
class ProxiedIntrospectionTests extends IntrospectionEndpointTestsUtils {

  @MockBean
  private OpaqueTokenIntrospector opaqueTokenIntrospector;

  @Test
  void testProxiedIntrospectionWithKnownProvider() throws Exception {

    String externalIssuer = "https://einstein.example.com";
    String clientId = "client-einstein";
    String scopes = "openid profile email";

    Map<String, Object> attrs = new HashMap<>();
    attrs.put("active", true);
    attrs.put("iss", externalIssuer);
    attrs.put("client_id", clientId);
    attrs.put("scope", scopes);

    OAuth2AuthenticatedPrincipal principal =
        new DefaultOAuth2AuthenticatedPrincipal(attrs, List.of());

    String token = buildPlainJwt(externalIssuer, "1234", clientId, scopes);

    when(opaqueTokenIntrospector.introspect(token)).thenReturn(principal);

    mvc
      .perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)

        .param("token", token)
        .param("token_type_hint", TokenTypeHint.ACCESS_TOKEN.name()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.iss", equalTo(externalIssuer)))
      .andExpect(jsonPath("$.client_id", equalTo(clientId)))
      .andExpect(jsonPath("$.scope", equalTo(scopes)));
  }

  @Test
  void testTokenInactiveWhenIntrospectionTrowsException() throws Exception {

    String issuer = "https://oppenheimer.example.com";
    String token = buildPlainJwt(issuer, "1234", "unknown", "openid");

    when(opaqueTokenIntrospector.introspect(token)).thenThrow(new RestClientException("Error"));

    mvc
      .perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param("token", token)
        .param("token_type_hint", TokenTypeHint.ACCESS_TOKEN.name()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
  }

}
