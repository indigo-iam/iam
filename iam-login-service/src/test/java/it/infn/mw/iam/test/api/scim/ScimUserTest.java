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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

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
  void patchUserAcceptsCaseInsensitiveOperationType() throws Exception {

    String token = clientCredentialsToken(StructuredScopeTestSupportConstants.SCIM_CLIENT_RW_ID,
        StructuredScopeTestSupportConstants.SCIM_CLIENT_RW_SECRET, "scim:read scim:write");

    ScimUser user = ScimUser.builder()
      .userName("scim-case-insensitive-patch-user")
      .name(ScimName.builder().givenName("Test").familyName("User").build())
      .addEmail(ScimEmail.builder().email("scim-case-insensitive@test.org").build())
      .build();

    var createResult =
        authorizedPost(SCIM_BASE + "/Users", token, mapper.writeValueAsString(user));
    assertEquals(201, createResult.getResponse().getStatus());

    JsonNode created = mapper.readTree(createResult.getResponse().getContentAsString());
    String userId = created.get("id").asText();

    ScimUserPatchRequest request = ScimUserPatchRequest.builder()
      .replace(ScimUser.builder().userName("scim-case-patch-updated").build())
      .build();

    ObjectNode patchJson = mapper.valueToTree(request);
    ((ObjectNode) patchJson.get("Operations").get(0)).put("op", "Replace");

    assertEquals(204,
        authorizedPatch(SCIM_BASE + "/Users/" + userId, token,
            mapper.writeValueAsString(patchJson)).getResponse().getStatus());

    var getResult = authorizedGet(SCIM_BASE + "/Users/" + userId, token);
    assertEquals(200, getResult.getResponse().getStatus());

    JsonNode updated = mapper.readTree(getResult.getResponse().getContentAsString());
    assertEquals("scim-case-patch-updated", updated.get("userName").asText());

    assertEquals(204,
        authorizedDelete(SCIM_BASE + "/Users/" + userId, token).getResponse().getStatus());
  }

  @Test
  void patchUserAcceptsPathBasedNativeValues() throws Exception {

    String token = clientCredentialsToken(StructuredScopeTestSupportConstants.SCIM_CLIENT_RW_ID,
        StructuredScopeTestSupportConstants.SCIM_CLIENT_RW_SECRET, "scim:read scim:write");

    ScimUser user = ScimUser.builder()
      .userName("scim-path-patch-user")
      .name(ScimName.builder().givenName("Initial").familyName("Person").build())
      .addEmail(ScimEmail.builder().email("scim-path-patch@test.org").build())
      .active(false)
      .build();

    var createResult =
        authorizedPost(SCIM_BASE + "/Users", token, mapper.writeValueAsString(user));
    assertEquals(201, createResult.getResponse().getStatus());

    JsonNode created = mapper.readTree(createResult.getResponse().getContentAsString());
    String userId = created.get("id").asText();

    String patchJson = """
        {
          "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          "Operations": [
            {"op": "Replace", "path": "userName", "value": "scim-path-updated"},
            {"op": "replace", "path": "name.givenName", "value": "Updated"},
            {"op": "replace", "path": "name.familyName", "value": "User"},
            {"op": "replace", "path": "emails[type eq \\"work\\"].value",
              "value": "scim-path-updated@test.org"},
            {"op": "replace", "path": "active", "value": true}
          ]
        }
        """;

    assertEquals(204,
        authorizedPatch(SCIM_BASE + "/Users/" + userId, token, patchJson).getResponse()
          .getStatus());

    var getResult = authorizedGet(SCIM_BASE + "/Users/" + userId, token);
    assertEquals(200, getResult.getResponse().getStatus());

    JsonNode updated = mapper.readTree(getResult.getResponse().getContentAsString());
    assertEquals("scim-path-updated", updated.get("userName").asText());
    assertEquals("scim-path-updated", updated.get("displayName").asText());
    assertEquals("Updated", updated.get("name").get("givenName").asText());
    assertEquals("User", updated.get("name").get("familyName").asText());
    assertEquals("scim-path-updated@test.org",
        updated.get("emails").get(0).get("value").asText());
    assertTrue(updated.get("active").asBoolean());

    assertEquals(204,
        authorizedDelete(SCIM_BASE + "/Users/" + userId, token).getResponse().getStatus());
  }

  @Test
  void pathBasedPatchRejectsUnsupportedAttributesWithoutDeserializationFailure() throws Exception {

    String token = clientCredentialsToken(StructuredScopeTestSupportConstants.SCIM_CLIENT_RW_ID,
        StructuredScopeTestSupportConstants.SCIM_CLIENT_RW_SECRET, "scim:read scim:write");

    ScimUser user = ScimUser.builder()
      .userName("scim-unsupported-path-user")
      .name(ScimName.builder().givenName("Test").familyName("User").build())
      .addEmail(ScimEmail.builder().email("scim-unsupported-path@test.org").build())
      .build();

    var createResult =
        authorizedPost(SCIM_BASE + "/Users", token, mapper.writeValueAsString(user));
    assertEquals(201, createResult.getResponse().getStatus());

    String userId = mapper.readTree(createResult.getResponse().getContentAsString())
      .get("id")
      .asText();

    for (String unsupportedPath : new String[] {"displayName", "externalId"}) {
      String patchJson = """
          {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
              "op": "Replace", "path": "%s", "value": "external-user"
            }]
          }
          """.formatted(unsupportedPath);

      var patchResult = authorizedPatch(SCIM_BASE + "/Users/" + userId, token, patchJson);
      String responseBody = patchResult.getResponse().getContentAsString();

      assertEquals(400, patchResult.getResponse().getStatus());
      assertTrue(responseBody.contains(unsupportedPath));
      assertFalse(responseBody.contains("Cannot construct instance"));
    }

    String mismatchedObjectPatch = """
        {
          "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          "Operations": [{
            "op": "Replace", "path": "displayName",
            "value": {"userName": "scim-path-bypass"}
          }]
        }
        """;

    var mismatchedObjectResult =
        authorizedPatch(SCIM_BASE + "/Users/" + userId, token, mismatchedObjectPatch);
    assertEquals(400, mismatchedObjectResult.getResponse().getStatus());
    assertTrue(mismatchedObjectResult.getResponse().getContentAsString().contains("displayName"));

    var getResult = authorizedGet(SCIM_BASE + "/Users/" + userId, token);
    assertEquals(200, getResult.getResponse().getStatus());
    assertEquals("scim-unsupported-path-user",
        mapper.readTree(getResult.getResponse().getContentAsString()).get("userName").asText());

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
