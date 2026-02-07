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
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;

public class IntrospectionAndRevocationTest extends OidcMockMvcTestSupport
    implements StructuredScopeTestSupportConstants {

  @Test
  void revokedTokenBecomesInactive() throws Exception {

    JsonNode token =
        assert200AndParse(postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials"),
            basicAuth(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET)));

    String accessToken = token.get("access_token").asText();

    // revoke
    assertEquals(200,
        postForm(REVOCATION_ENDPOINT, Map.of("token", accessToken),
            basicAuth(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET)).getResponse()
              .getStatus());

    // introspect
    JsonNode introspection = assert200AndParse(postForm(INTROSPECTION_ENDPOINT,
        Map.of("token", accessToken), basicAuth(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET)));

    assertFalse(introspection.get("active").asBoolean());
  }

  @Test
  void introspectionFailsWithoutAuth() throws Exception {

    var result = postForm(INTROSPECTION_ENDPOINT, Map.of("token", "whatever"), null);

    assertEquals(401, result.getResponse().getStatus());
  }
}
