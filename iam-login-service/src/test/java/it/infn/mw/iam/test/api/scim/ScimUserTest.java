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
package it.infn.mw.iam.test.api.scim;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;

class ScimUserTest extends ScimMockMvcTestSupport {

  @Test
  void fullUserLifecycleWithRWClient() throws Exception {

    String token = clientCredentialsToken(StructuredScopeTestSupportConstants.SCIM_CLIENT_RW_ID,
        StructuredScopeTestSupportConstants.SCIM_CLIENT_RW_SECRET, "scim:read scim:write");

    ScimUser user = ScimUser.builder()
      .userName("scim-test-user")
      .name(ScimName.builder().givenName("Test").familyName("User").build())
      .addEmail(ScimEmail.builder().email("scim@test.org").build())
      .build();

    // Create user
    String createJson = mapper.writeValueAsString(user);

    var createResult = authorizedPost(SCIM_BASE + "/Users", token, createJson);
    assertEquals(201, createResult.getResponse().getStatus());

    JsonNode created = mapper.readTree(createResult.getResponse().getContentAsString());
    String userId = created.get("id").asText();

    ScimUserPatchRequest request = ScimUserPatchRequest.builder()
      .replace(ScimUser.builder().userName("scim-updated-user").build())
      .build();

    // Update user
    String patchJson = mapper.writeValueAsString(request);

    assertEquals(204,
        authorizedPatch(SCIM_BASE + "/Users/" + userId, token, patchJson).getResponse()
          .getStatus());

    // Delete
    assertEquals(204,
        authorizedDelete(SCIM_BASE + "/Users/" + userId, token).getResponse().getStatus());
  }

  @Test
  void readOnlyClientCannotCreateUser() throws Exception {

    String token = clientCredentialsToken(StructuredScopeTestSupportConstants.SCIM_CLIENT_RO_ID,
        StructuredScopeTestSupportConstants.SCIM_CLIENT_RO_SECRET, "scim:read");

    ScimUser user = ScimUser.builder()
      .userName("failing-user")
      .name(ScimName.builder().givenName("Test").familyName("User").build())
      .addEmail(ScimEmail.builder().email("scim@test.org").build())
      .build();

    String createJson = mapper.writeValueAsString(user);

    var result = authorizedPost(SCIM_BASE + "/Users", token, createJson);

    assertEquals(403, result.getResponse().getStatus());
  }

}
