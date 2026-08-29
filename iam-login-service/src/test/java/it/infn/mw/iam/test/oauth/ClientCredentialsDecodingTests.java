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
package it.infn.mw.iam.test.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ClientCredentialsDecodingTests {

  @Autowired
  private MockMvc mvc;

  @Test
  void decodeURLEncodedClientCredentialsAtTokenEndpoint() throws Exception {

    String clientId = "https://federated-client.com";
    String clientSecret = "secret";

    // URL encode client_id and client_secret
    String encodedClientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
    String encodedClientSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);

    String credentials = Base64.getEncoder()
      .encodeToString(
          (encodedClientId + ":" + encodedClientSecret).getBytes(StandardCharsets.UTF_8));

    String tokenResponse = mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .header("Authorization", "Basic " + credentials))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode json = new ObjectMapper().readTree(tokenResponse);
    String accessToken = json.get("access_token").asText();
    SignedJWT jwt = SignedJWT.parse(accessToken);
    assertEquals(clientId, jwt.getJWTClaimsSet().getStringClaim("client_id"));
  }
}
