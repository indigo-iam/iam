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
package it.infn.mw.iam.test.scim.user;

import static it.infn.mw.iam.api.scim.model.ScimListResponse.SCHEMA;
import static it.infn.mw.iam.test.TestUtils.TOTAL_USERS_COUNT;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.scim.ScimUtils.ParamsBuilder;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@IamMockMvcIntegrationTest
@SpringBootTest(
  classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
  webEnvironment = WebEnvironment.MOCK)
@WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE})
class ScimUserProvisioningListTests {

  @Autowired
  private ScimRestUtilsMvc scimUtils;

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
  void testNoParameterListRequest() throws Exception {

    scimUtils.getUsers()
      .andExpect(jsonPath("$.totalResults", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(100)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(100))));
  }

  @Test
  @WithMockUser(username = "test", roles = "READER")
  void testReaderCanGetListOfUsers() throws Exception {
    testNoParameterListRequest();
  }

  @Test
  @WithMockUser(username = "test", roles = "ADMIN")
  void testAdminCanNotSeePemEncodedCertificate() throws Exception {
    testPemEncodedCertificateDoesNotExist();
  }

  @Test
  @WithMockUser(username = "test", roles = "READER")
  void testReaderCanNotSeePemEncodedCertificate() throws Exception {
    testPemEncodedCertificateDoesNotExist();
  }

  private void testPemEncodedCertificateDoesNotExist() throws Exception {
    scimUtils.getUsers()
      .andExpect(jsonPath("$.totalResults", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(100))))
      .andExpect(jsonPath("$.Resources[0].userName", equalTo("admin")))
      .andExpect(jsonPath("$.Resources[0].urn:indigo-dc:scim:schemas:IndigoUser.certificates",
          hasSize(equalTo(1))))
      .andExpect(
          jsonPath("$.Resources[0].urn:indigo-dc:scim:schemas:IndigoUser.certificates[0].subjectDn",
              equalTo("CN=test2,O=IGI,C=IT")))
      .andExpect(jsonPath(
          "$.Resources[0].urn:indigo-dc:scim:schemas:IndigoUser.certificates[0].pemEncodedCertificate")
            .doesNotExist());
  }

  @Test
  void testCountAs10Returns10Items() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().count(10).build())
      .andExpect(jsonPath("$.totalResults", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(10)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(10))));
  }

  @Test
  void testCount1Returns1Item() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().count(1).build())
      .andExpect(jsonPath("$.totalResults", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(1))));
  }

  @Test
  void testCountShouldBeLimitedToOneHundred() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().count(1000).build())
      .andExpect(jsonPath("$.totalResults", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(100)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(100))));
  }

  @Test
  void testNegativeCountBecomesZero() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().count(-10).build())
      .andExpect(jsonPath("$.totalResults", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.itemsPerPage").doesNotExist())
      .andExpect(jsonPath("$.startIndex").doesNotExist())
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", is(empty())));
  }

  @Test
  void testInvalidStartIndex() throws Exception {

    int startIndex = Long.valueOf(TOTAL_USERS_COUNT).intValue() + 1;
    scimUtils.getUsers(ParamsBuilder.builder().startIndex(startIndex).build())
      .andExpect(jsonPath("$.totalResults", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(0)))
      .andExpect(jsonPath("$.startIndex", equalTo(TOTAL_USERS_COUNT + 1)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources").isEmpty());
  }

  @Test
  void testRightEndPagination() throws Exception {

    int startIndex = Long.valueOf(TOTAL_USERS_COUNT).intValue() - 5;
    scimUtils.getUsers(ParamsBuilder.builder().startIndex(startIndex).count(10).build())
      .andExpect(jsonPath("$.totalResults", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(6)))
      .andExpect(jsonPath("$.startIndex", equalTo(TOTAL_USERS_COUNT - 5)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(6))));
  }

  @Test
  void testLastElementPagination() throws Exception {

    int startIndex = Long.valueOf(TOTAL_USERS_COUNT).intValue();
    scimUtils.getUsers(ParamsBuilder.builder().startIndex(startIndex).count(2).build())
      .andExpect(jsonPath("$.totalResults", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.startIndex", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(1))));
  }

  @Test
  void testFirstElementPagination() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().startIndex(1).count(5).build())
      .andExpect(jsonPath("$.totalResults", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(5)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(5))));
  }
}
