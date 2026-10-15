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
package it.infn.mw.iam.test.scim.discovery;

import static it.infn.mw.iam.api.scim.model.ScimConstants.AARC_GROUP_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimConstants.AARC_USER_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_GROUP_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_USER_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.everyItem;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
@WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read"})
@TestPropertySource(properties = "scim.enable-aarc=true")
class ScimDiscoveryAarcEnabledEndpointTests {

  private static final String RESOURCE_TYPES_ENDPOINT = "/scim/ResourceTypes";
  private static final String SCHEMAS_ENDPOINT = "/scim/Schemas";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @BeforeEach
  void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @AfterEach
  void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  void testSchemasEndpointReturnsAarcSchemasWhenEnabled() throws Exception {

    mvc.perform(get(SCHEMAS_ENDPOINT).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(6)))
      .andExpect(jsonPath("$.Resources", hasSize(6)))
      .andExpect(jsonPath("$.Resources[*].id", hasItem(AARC_USER_SCHEMA)))
      .andExpect(jsonPath("$.Resources[*].id", hasItem(AARC_GROUP_SCHEMA)));
  }

  @Test
  void testUserResourceTypeDeclaresAarcExtensionWhenEnabled() throws Exception {

    mvc.perform(get(RESOURCE_TYPES_ENDPOINT + "/User").contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(
          jsonPath("$.schemaExtensions[?(@.schema == '" + INDIGO_USER_SCHEMA + "')].required",
              hasItem(false)))
      .andExpect(jsonPath("$.schemaExtensions[?(@.schema == '" + AARC_USER_SCHEMA + "')].required",
          hasItem(false)));
  }

  @Test
  void testGroupResourceTypeDeclaresAarcExtensionWhenEnabled() throws Exception {

    mvc.perform(get(RESOURCE_TYPES_ENDPOINT + "/Group").contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(
          jsonPath("$.schemaExtensions[?(@.schema == '" + INDIGO_GROUP_SCHEMA + "')].required",
              hasItem(false)))
      .andExpect(jsonPath("$.schemaExtensions[?(@.schema == '" + AARC_GROUP_SCHEMA + "')].required",
          hasItem(false)));
  }

  @Test
  void testAarcGroupSchemaDeclaresMembersAsReadOnly() throws Exception {

    mvc.perform(get(SCHEMAS_ENDPOINT + "/{id}", AARC_GROUP_SCHEMA).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.attributes[?(@.name == 'members')].type", hasItem("complex")))
      .andExpect(jsonPath("$.attributes[?(@.name == 'members')].multiValued", hasItem(true)))
      .andExpect(jsonPath("$.attributes[?(@.name == 'members')].mutability", hasItem("readOnly")))
      .andExpect(jsonPath("$.attributes[?(@.name == 'members')].subAttributes[*].name",
          hasItems("value", "display", "$ref")))
      .andExpect(jsonPath("$.attributes[?(@.name == 'members')].subAttributes[*].mutability",
          everyItem(equalTo("readOnly"))));
  }
}
