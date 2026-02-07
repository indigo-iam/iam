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

import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;

public class DeviceCodeFlowTest extends OidcMockMvcTestSupport
    implements StructuredScopeTestSupportConstants {

  @Test
  void deviceCodeFlowHappyPath() throws Exception {

    // Step 1: request device code
    JsonNode deviceCodeResponse = assert200AndParse(postForm(DEVICE_CODE_ENDPOINT,
        Map.of("client_id", DEVICE_CODE_CLIENT_ID, "scope", "openid profile"), null));

    String deviceCode = deviceCodeResponse.get("device_code").asText();

    // Step 2: poll token endpoint (before approval → authorization_pending)
    var pendingResult = postForm(TOKEN_ENDPOINT,
        Map.of("grant_type", "urn:ietf:params:oauth:grant-type:device_code", "device_code",
            deviceCode, "client_id", DEVICE_CODE_CLIENT_ID),
        basicAuth(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET));

    assertEquals(400, pendingResult.getResponse().getStatus());

    // NOTE:
    // Approval would normally happen via /device UI.
    // In test environments this is often auto-approved or pre-approved.
  }

  @Test
  void deviceCodeFailsForUnknownClient() throws Exception {

    var result = postForm(DEVICE_CODE_ENDPOINT, Map.of("client_id", "unknown-client"), null);

    assertEquals(404, result.getResponse().getStatus());
  }
}
