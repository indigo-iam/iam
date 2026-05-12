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
package it.infn.mw.iam.test.scim.nodb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import org.junit.jupiter.api.Test;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.JsonNode;

@Transactional
class ScimApiAccessTests extends ScimTestSupport {

  @Test
  void userLifecycle() throws Exception {

    String token = scimRwToken();

    JsonNode user = createScimUser(token, random("user"));
    String userId = user.get("id").asText();

    JsonNode fetched = getResource(token, SCIM_USERS + "/" + userId);
    assertEquals(userId, fetched.get("id").asText());

    deleteResource(token, SCIM_USERS + "/" + userId);
  }

  @Test
  void userAddedToGroup() throws Exception {

    String token = passwordToken("scim:read scim:write", "admin", "password");

    JsonNode user = createScimUser(token, random("member"));
    JsonNode group = createScimGroup(token, random("group"));

    addUserToGroup(token, group.get("id").asText(), user.get("id").asText());

    JsonNode updatedUser = getResource(token, SCIM_USERS + "/" + user.get("id").asText());

    String uuidGroup = updatedUser.get("groups").get(0).get("value").asText();
    assertEquals(uuidGroup, group.get("id").asText());
  }

  @Test
  void userAddedToGroupLegacy() throws Exception {

    String token = passwordToken("scim:read scim:write", "admin", "password");

    JsonNode user = createScimUser(token, random("member"));
    JsonNode group = createScimGroup(token, random("group"));

    addUserToGroupLegacy(token, group.get("id").asText(), user.get("id").asText());

    JsonNode updatedUser = getResource(token, SCIM_USERS + "/" + user.get("id").asText());

    String uuidGroup = updatedUser.get("groups").get(0).get("value").asText();
    assertEquals(uuidGroup, group.get("id").asText());
  }

  @Test
  void wrongGroupContentOnCreation() throws Exception {

    String token = scimRwToken();

    String json = """
        {
          "displayWrongName": "Engineers"
        }
        """;

    var result = mockMvc
      .perform(post(SCIM_GROUPS).header("Authorization", "Bearer " + token)
        .contentType("application/scim+json")
        .content(json))
      .andReturn();

    assertEquals(400, result.getResponse().getStatus());
  }

  @Test
  void validIdTokenIsNotEnoughToAccessScimApi() throws Exception {

    String accessToken = passwordToken("scim:read scim:write", "admin", "password");

    JsonNode user = createScimUser(accessToken, random("member"));
    JsonNode group = createScimGroup(accessToken, random("group"));

    String idToken = passwordIdToken("openid profile", "admin", "password");

    assertEquals(401,
        getResourceResult(idToken, SCIM_USERS + "/" + user.get("id").asText()).getResponse()
          .getStatus());

    assertEquals(401,
        getResourceResult(idToken, SCIM_GROUPS + "/" + group.get("id").asText()).getResponse()
          .getStatus());
  }
}
