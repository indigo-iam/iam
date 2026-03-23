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

class TokenExchangeTests extends OidcMockMvcTestSupport {

  @Test
  void tokenExchangeSuccess() throws Exception {

    JsonNode original =
        assert200AndParse(postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials"),
            CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET));

    String subjectToken = original.get("access_token").asText();

    JsonNode exchanged = assert200AndParse(postForm(TOKEN_ENDPOINT,
        Map.of("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token",
            subjectToken, "subject_token_type", "urn:ietf:params:oauth:token-type:access_token",
            "scope", "openid profile"),
        EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET));

    assertTrue(exchanged.has("access_token"));
  }

  @Test
  void tokenExchangeFailsForInvalidSubjectToken() throws Exception {

    var result = postForm(TOKEN_ENDPOINT,
        Map.of("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token",
            "invalid", "subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
        EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET);

    assertEquals(400, result.getResponse().getStatus());
  }
}
