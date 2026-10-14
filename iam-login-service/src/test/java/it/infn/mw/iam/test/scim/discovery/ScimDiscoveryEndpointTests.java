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

import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_GROUP_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_USER_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_BULK_MAX_OPERATIONS;
import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_BULK_MAX_PAYLOAD_SIZE;
import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.model.ScimResourceType;
import it.infn.mw.iam.api.scim.model.ScimSchema;
import it.infn.mw.iam.api.scim.model.ScimServiceProviderConfig;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
@WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read"})
class ScimDiscoveryEndpointTests {

  private static final String SERVICE_PROVIDER_CONFIG_ENDPOINT = "/scim/ServiceProviderConfig";
  private static final String RESOURCE_TYPES_ENDPOINT = "/scim/ResourceTypes";
  private static final String SCHEMAS_ENDPOINT = "/scim/Schemas";
  private static final String FILTER_NOT_SUPPORTED_MSG =
      "Filtering is not supported on this endpoint";

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
  void testServiceProviderConfigEndpointReturnsSupportedCapabilities() throws Exception {

    mvc.perform(get(SERVICE_PROVIDER_CONFIG_ENDPOINT).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(content().contentType(SCIM_CONTENT_TYPE))
      .andExpect(
          jsonPath("$.schemas", hasItem(ScimServiceProviderConfig.SERVICE_PROVIDER_CONFIG_SCHEMA)))
      .andExpect(jsonPath("$.patch.supported", equalTo(true)))
      .andExpect(jsonPath("$.bulk.supported", equalTo(true)))
      .andExpect(jsonPath("$.bulk.maxOperations", equalTo(SCIM_BULK_MAX_OPERATIONS)))
      .andExpect(jsonPath("$.bulk.maxPayloadSize", equalTo(SCIM_BULK_MAX_PAYLOAD_SIZE)))
      .andExpect(jsonPath("$.filter.supported", equalTo(true)))
      .andExpect(jsonPath("$.filter.maxResults", equalTo(100)))
      .andExpect(jsonPath("$.authenticationSchemes[0].type", equalTo("oauthbearertoken")));
  }

  @Test
  void testResourceTypesEndpointReturnsUserAndGroupResourceTypes() throws Exception {

    mvc.perform(get(RESOURCE_TYPES_ENDPOINT).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(content().contentType(SCIM_CONTENT_TYPE))
      .andExpect(jsonPath("$.schemas", hasItem(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.totalResults", equalTo(2)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(2)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.Resources", hasSize(2)))
      .andExpect(jsonPath("$.Resources[?(@.id == 'User')].schema", hasItem(ScimUser.USER_SCHEMA)))
      .andExpect(jsonPath("$.Resources[?(@.id == 'Group')].schema",
          hasItem("urn:ietf:params:scim:schemas:core:2.0:Group")))
      .andExpect(jsonPath("$.Resources[?(@.id == 'User')].meta.location",
          hasItem(containsString("/scim/ResourceTypes/User"))))
      .andExpect(jsonPath("$.Resources[?(@.id == 'Group')].meta.location",
          hasItem(containsString("/scim/ResourceTypes/Group"))));
  }

  @Test
  void testResourceTypesEndpointSupportsSingleResourceRetrieval() throws Exception {

    mvc.perform(get(RESOURCE_TYPES_ENDPOINT + "/User").contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(content().contentType(SCIM_CONTENT_TYPE))
      .andExpect(jsonPath("$.schemas", hasItem(ScimResourceType.RESOURCE_TYPE_SCHEMA)))
      .andExpect(jsonPath("$.id", equalTo("User")))
      .andExpect(jsonPath("$.name", equalTo("User")))
      .andExpect(jsonPath("$.endpoint", equalTo("/Users")))
      .andExpect(jsonPath("$.schema", equalTo(ScimUser.USER_SCHEMA)))
      .andExpect(jsonPath("$.meta.resourceType", equalTo("ResourceType")));
  }

  @Test
  void testResourceTypeEndpointReturnsNotFoundForUnknownType() throws Exception {

    mvc.perform(get(RESOURCE_TYPES_ENDPOINT + "/Unknown").contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.status", equalTo("404")))
      .andExpect(jsonPath("$.detail", equalTo("No ResourceType found for 'Unknown'")));
  }

  @Test
  void testSchemasEndpointReturnsSupportedSchemas() throws Exception {

    mvc.perform(get(SCHEMAS_ENDPOINT).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(content().contentType(SCIM_CONTENT_TYPE))
      .andExpect(jsonPath("$.schemas", hasItem(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.totalResults", equalTo(4)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(4)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.Resources", hasSize(4)))
      .andExpect(
          jsonPath("$.Resources[?(@.id == '" + ScimUser.USER_SCHEMA + "')].name", hasItem("User")))
      .andExpect(jsonPath("$.Resources[?(@.id == '" + INDIGO_USER_SCHEMA + "')].name",
          hasItem("IndigoUser")))
      .andExpect(jsonPath("$.Resources[?(@.id == '" + INDIGO_GROUP_SCHEMA + "')].name",
          hasItem("IndigoGroup")));
  }

  @Test
  void testSchemasEndpointSupportsSingleSchemaRetrieval() throws Exception {

    mvc.perform(
        get(SCHEMAS_ENDPOINT + "/{id}", ScimUser.USER_SCHEMA).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(content().contentType(SCIM_CONTENT_TYPE))
      .andExpect(jsonPath("$.schemas", hasItem(ScimSchema.SCHEMA_SCHEMA)))
      .andExpect(jsonPath("$.id", equalTo(ScimUser.USER_SCHEMA)))
      .andExpect(jsonPath("$.name", equalTo("User")))
      .andExpect(jsonPath("$.meta.resourceType", equalTo("Schema")))
      .andExpect(
          jsonPath("$.meta.location", containsString("/scim/Schemas/" + ScimUser.USER_SCHEMA)))
      .andExpect(jsonPath("$.attributes[?(@.name == 'userName')].required", hasItem(true)));
  }

  @Test
  void testUserSchemaDeclaresOnlySupportedCoreUserAttributes() throws Exception {

    mvc.perform(
        get(SCHEMAS_ENDPOINT + "/{id}", ScimUser.USER_SCHEMA).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.attributes[*].name",
          hasItems("userName", "password", "name", "displayName", "nickName", "profileUrl",
              "locale", "timezone", "active", "emails", "addresses", "photos", "groups")))
      .andExpect(jsonPath("$.attributes[*].name", not(hasItem("title"))))
      .andExpect(jsonPath("$.attributes[*].name", not(hasItem("userType"))))
      .andExpect(jsonPath("$.attributes[*].name", not(hasItem("preferredLanguage"))))
      .andExpect(jsonPath("$.attributes[?(@.name == 'name')].subAttributes[*].name",
          hasItems("formatted", "givenName", "familyName")))
      .andExpect(jsonPath("$.attributes[?(@.name == 'name')].subAttributes[*].name",
          not(hasItem("middleName"))))
      .andExpect(jsonPath("$.attributes[?(@.name == 'name')].subAttributes[*].name",
          not(hasItem("honorificPrefix"))))
      .andExpect(jsonPath("$.attributes[?(@.name == 'name')].subAttributes[*].name",
          not(hasItem("honorificSuffix"))))
      .andExpect(jsonPath("$.attributes[?(@.name == 'name')].required", hasItem(true)))
      .andExpect(jsonPath(
          "$.attributes[?(@.name == 'name')].subAttributes[?(@.name == 'givenName')].required",
          hasItem(true)))
      .andExpect(jsonPath(
          "$.attributes[?(@.name == 'name')].subAttributes[?(@.name == 'familyName')].required",
          hasItem(true)))
      .andExpect(jsonPath("$.attributes[?(@.name == 'password')].mutability",
          hasItem("writeOnly")))
      .andExpect(jsonPath("$.attributes[?(@.name == 'password')].returned", hasItem("never")))
      .andExpect(jsonPath("$.attributes[?(@.name == 'emails')].required", hasItem(true)))
      .andExpect(jsonPath(
          "$.attributes[?(@.name == 'emails')].subAttributes[?(@.name == 'value')].required",
          hasItem(true)))
      .andExpect(
          jsonPath("$.attributes[?(@.name == 'displayName')].mutability", hasItem("readOnly")))
      .andExpect(
          jsonPath("$.attributes[?(@.name == 'nickName')].mutability", hasItem("readOnly")))
      .andExpect(
          jsonPath("$.attributes[?(@.name == 'profileUrl')].mutability", hasItem("readOnly")))
      .andExpect(jsonPath("$.attributes[?(@.name == 'locale')].mutability", hasItem("readOnly")))
      .andExpect(
          jsonPath("$.attributes[?(@.name == 'timezone')].mutability", hasItem("readOnly")))
      .andExpect(jsonPath(
          "$.attributes[?(@.name == 'emails')].subAttributes[?(@.name == 'type')].mutability",
          hasItem("readOnly")))
      .andExpect(jsonPath(
          "$.attributes[?(@.name == 'emails')].subAttributes[?(@.name == 'primary')].mutability",
          hasItem("readOnly")))
      .andExpect(jsonPath(
          "$.attributes[?(@.name == 'addresses')].subAttributes[?(@.name == 'type')].mutability",
          hasItem("readOnly")))
      .andExpect(jsonPath(
          "$.attributes[?(@.name == 'addresses')].subAttributes[?(@.name == 'primary')].mutability",
          hasItem("readOnly")))
      .andExpect(jsonPath(
          "$.attributes[?(@.name == 'photos')].subAttributes[?(@.name == 'type')].mutability",
          hasItem("readOnly")))
      .andExpect(jsonPath("$.attributes[?(@.name == 'groups')].mutability", hasItem("readOnly")));
  }

  @Test
  void testGroupSchemaMutabilityMatchesProvisioningBehavior() throws Exception {

    mvc.perform(
        get(SCHEMAS_ENDPOINT + "/{id}", ScimGroup.GROUP_SCHEMA).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.attributes[?(@.name == 'displayName')].mutability",
          hasItem("readWrite")))
      .andExpect(jsonPath(
          "$.attributes[?(@.name == 'members')].subAttributes[?(@.name == 'value')].mutability",
          hasItem("readWrite")))
      .andExpect(jsonPath(
          "$.attributes[?(@.name == 'members')].subAttributes[?(@.name == 'display')].mutability",
          hasItem("readOnly")))
      .andExpect(jsonPath(
          "$.attributes[?(@.name == 'members')].subAttributes[?(@.name == '$ref')].mutability",
          hasItem("readOnly")));
  }

  @Test
  void testIndigoUserSchemaDeclaresAllRepositoryExtensionAttributes() throws Exception {

    mvc.perform(get(SCHEMAS_ENDPOINT + "/{id}", INDIGO_USER_SCHEMA).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.attributes[*].name",
          hasItems("serviceAccount", "affiliation", "sshKeys", "oidcIds", "samlIds",
              "certificates", "aupSignatureTime", "endTime", "labels", "authorities",
              "attributes", "managedGroups")))
      .andExpect(jsonPath("$.attributes[?(@.name == 'sshKeys')].subAttributes[*].name",
          hasItems("display", "primary", "fingerprint", "value", "created", "lastModified")))
      .andExpect(jsonPath("$.attributes[?(@.name == 'certificates')].subAttributes[*].name",
          hasItems("display", "primary", "subjectDn", "issuerDn", "pemEncodedCertificate",
              "created", "lastModified", "hasProxyCertificate", "proxyExpirationTime")));
  }

  @Test
  void testIndigoGroupSchemaDeclaresAllRepositoryExtensionAttributes() throws Exception {

    mvc.perform(get(SCHEMAS_ENDPOINT + "/{id}", INDIGO_GROUP_SCHEMA).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(
          jsonPath("$.attributes[*].name", hasItems("parentGroup", "description", "labels")))
      .andExpect(jsonPath("$.attributes[?(@.name == 'parentGroup')].mutability",
          hasItem("immutable")))
      .andExpect(jsonPath("$.attributes[?(@.name == 'description')].mutability",
          hasItem("readWrite")))
      .andExpect(jsonPath("$.attributes[?(@.name == 'parentGroup')].subAttributes[*].name",
          hasItems("value", "display", "$ref")));
  }

  @Test
  void testSchemaEndpointReturnsNotFoundForUnknownSchema() throws Exception {

    mvc.perform(get(SCHEMAS_ENDPOINT + "/{id}", "urn:test:unknown").contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.status", equalTo("404")))
      .andExpect(jsonPath("$.detail", equalTo("No Schema found for 'urn:test:unknown'")));
  }

  @Test
  void testSchemasListWithFilterReturnsForbidden() throws Exception {

    mvc.perform(get(SCHEMAS_ENDPOINT).contentType(SCIM_CONTENT_TYPE).param("filter", "id pr"))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.status", equalTo("403")))
      .andExpect(jsonPath("$.detail", equalTo(FILTER_NOT_SUPPORTED_MSG)));
  }

  @Test
  void testResourceTypesListWithFilterReturnsForbidden() throws Exception {

    mvc.perform(
        get(RESOURCE_TYPES_ENDPOINT).contentType(SCIM_CONTENT_TYPE).param("filter", "id pr"))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.status", equalTo("403")))
      .andExpect(jsonPath("$.detail", equalTo(FILTER_NOT_SUPPORTED_MSG)));
  }
}
