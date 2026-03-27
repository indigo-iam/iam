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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.test.util.oidc.OidcMockMvcTestSupport;

public class ScimTestSupport extends OidcMockMvcTestSupport {

  protected JsonNode createScimUser(String token, String username) throws Exception {

    String json = """
        {
          "userName": "%s",
          "name": {
            "givenName": "Test",
            "familyName": "User"
          },
          "emails": [{
            "value": "%s@test.local"
          }]
        }
        """.formatted(username, username);

    var result = mockMvc
      .perform(post(SCIM_USERS).header("Authorization", "Bearer " + token)
        .contentType("application/scim+json")
        .content(json))
      .andReturn();

    assertEquals(201, result.getResponse().getStatus());

    return mapper.readTree(result.getResponse().getContentAsString());
  }

  protected JsonNode createScimGroup(String token, String displayName) throws Exception {

    String json = """
        {
          "displayName": "%s"
        }
        """.formatted(displayName);

    var result = mockMvc
      .perform(post(SCIM_GROUPS).header("Authorization", "Bearer " + token)
        .contentType("application/scim+json")
        .content(json))
      .andReturn();

    assertEquals(201, result.getResponse().getStatus());

    return mapper.readTree(result.getResponse().getContentAsString());
  }

  protected JsonNode getMe(String token) throws Exception {

    var result =
        mockMvc.perform(get(SCIM_ME).header("Authorization", "Bearer " + token)).andReturn();

    assertEquals(200, result.getResponse().getStatus());

    return mapper.readTree(result.getResponse().getContentAsString());
  }

  protected void addUserToGroup(String token, String groupId, String userId) throws Exception {

    String patch = """
        {
          "Operations": [{
            "op": "add",
            "path": "members",
            "value": [{
              "value": "%s"
            }]
          }]
        }
        """.formatted(userId);

    var result = mockMvc
      .perform(patch(SCIM_GROUPS + "/" + groupId).header("Authorization", "Bearer " + token)
        .contentType("application/scim+json")
        .content(patch))
      .andReturn();

    assertEquals(204, result.getResponse().getStatus());
  }

  protected JsonNode getResource(String token, String url) throws Exception {

    var result = getResourceResult(token, url);

    assertEquals(200, result.getResponse().getStatus());

    return mapper.readTree(result.getResponse().getContentAsString());
  }

  protected MvcResult getResourceResult(String token, String url) throws Exception {

    return mockMvc.perform(get(url).header("Authorization", "Bearer " + token)).andReturn();
  }

  protected void deleteResource(String token, String url) throws Exception {

    var result =
        mockMvc.perform(delete(url).header("Authorization", "Bearer " + token)).andReturn();

    assertEquals(204, result.getResponse().getStatus());
  }

  protected String scimRwToken() throws Exception {
    return clientCredentialsToken(
        SCIM_CLIENT_RW_ID,
        SCIM_CLIENT_RW_SECRET,
        "scim:read scim:write"
    );
  }

  protected String scimRoToken() throws Exception {
    return clientCredentialsToken(
        SCIM_CLIENT_RO_ID,
        SCIM_CLIENT_RO_SECRET,
        "scim:read"
    );
  }

  protected String random(String prefix) {
    return prefix + "-" + System.nanoTime();
  }
}
