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
package it.infn.mw.iam.test.util.oauth;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class OAuthTokenTestUtils {

  private OAuthTokenTestUtils() {}

  public static String clientCredentialsToken(MockMvc mvc, ObjectMapper mapper, String clientId,
      String clientSecret, String... scopes) throws Exception {

    String response = mvc
      .perform(post("/token").with(httpBasic(clientId, clientSecret))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("grant_type", "client_credentials")
        .param("scope", String.join(" ", scopes)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode tokenResponse = mapper.readTree(response);

    String accessToken = tokenResponse.path("access_token").asText();

    if (accessToken.isBlank()) {
      throw new AssertionError("Token endpoint returned no access_token");
    }

    if (!"Bearer".equalsIgnoreCase(tokenResponse.path("token_type").asText())) {
      throw new AssertionError("Expected a Bearer access token");
    }

    // If scope is omitted, OAuth defines it as identical to the requested scope.
    if (tokenResponse.has("scope")) {
      String grantedScope = tokenResponse.path("scope").asText().trim();

      Set<String> grantedScopes = grantedScope.isEmpty() ? Set.of()
          : new HashSet<>(Arrays.asList(grantedScope.split("\\s+")));

      if (!grantedScopes.containsAll(Arrays.asList(scopes))) {
        throw new AssertionError("Token endpoint did not grant all requested scopes");
      }
    }

    return accessToken;
  }

  public static RequestPostProcessor bearerToken(String accessToken) {

    if (accessToken == null || accessToken.isBlank()) {
      throw new IllegalArgumentException("Access token must not be blank");
    }

    return request -> {
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
      return request;
    };
  }
}
