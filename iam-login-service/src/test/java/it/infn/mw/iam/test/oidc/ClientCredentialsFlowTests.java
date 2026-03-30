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
package it.infn.mw.iam.test.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.test.util.oidc.OidcMockMvcTestSupport;

class ClientCredentialsFlowTests extends OidcMockMvcTestSupport {

  @Test
  void clientCredentialsSuccess() throws Exception {

    JsonNode json = assert200AndParse(
        postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials", "scope", "openid"),
            CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET));

    assertTrue(json.has("access_token"));
    assertEquals("Bearer", json.get("token_type").asText());
  }

  @Test
  void clientCredentialsFailsWithWrongSecret() throws Exception {

    var result = postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials"),
        CLIENT_CREDENTIALS_CLIENT_ID, "wrong-secret");

    assertEquals(401, result.getResponse().getStatus());
  }
}
