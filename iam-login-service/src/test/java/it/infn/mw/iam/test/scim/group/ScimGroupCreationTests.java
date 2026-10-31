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
package it.infn.mw.iam.test.scim.group;

import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.test.scim.ScimUtils;
import it.infn.mw.iam.test.util.oauth.OAuthTokenTestUtils;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class ScimGroupCreationTests {

  static final String GROUP_URI = ScimUtils.getGroupsLocation();

  static final String SCIM_CLIENT_ID = "scim-client-rw";
  static final String SCIM_CLIENT_SECRET = "secret";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper objectMapper;

  private String scimAccessToken;

  @BeforeEach
  void setup() throws Exception {
    scimAccessToken = OAuthTokenTestUtils.clientCredentialsToken(mvc, objectMapper, SCIM_CLIENT_ID,
        SCIM_CLIENT_SECRET, "scim:read", "scim:write");
  }

  @Test
  void testCreateGroupWithAnExistingName() throws Exception {

    String name = "Group-Name";
    ScimGroup group = ScimGroup.builder(name).build();

    String result = mvc
      .perform(post(GROUP_URI).header(AUTHORIZATION, "Bearer " + scimAccessToken)
        .contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(group)))
      .andExpect(status().isCreated())
      .andReturn()
      .getResponse()
      .getContentAsString();

    ScimGroup createdGroup = objectMapper.readValue(result, ScimGroup.class);

    mvc
      .perform(get(createdGroup.getMeta().getLocation()).header(AUTHORIZATION,
          "Bearer " + scimAccessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.displayName", equalTo(name)));

    // Create a group with the same name.
    mvc
      .perform(post(GROUP_URI).header(AUTHORIZATION, "Bearer " + scimAccessToken)
        .contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(group)))
      .andExpect(status().isConflict());
  }
}
