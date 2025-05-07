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

import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_WRITE_SCOPE;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsStringIgnoringCase;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;


import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.scim.ScimUtils.ParamsBuilder;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_USER_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimListResponse.SCHEMA;
import static it.infn.mw.iam.test.TestUtils.TOTAL_USERS_COUNT;


import org.springframework.http.HttpStatus;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE})
public class ScimUserProvisioningFilteringTests {

  @Autowired
  private ScimRestUtilsMvc scimUtils;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }



  @Test
  public void testFilteringGivenNameEqPositive() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().filters("givenName eq Admin").build())
      .andExpect(jsonPath("$.totalResults", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(1))))
      .andExpect(jsonPath("$.Resources[0].id", equalTo("73f16d93-2441-4a50-88ff-85360d78c6b5")))
      .andExpect(jsonPath("$.Resources[0].name.givenName", equalTo("Admin")))
      .andExpect(jsonPath("$.Resources[0].schemas").exists())
      .andExpect(jsonPath("$.Resources[0].userName").exists())
      .andExpect(jsonPath("$.Resources[0].emails").exists())
      .andExpect(jsonPath("$.Resources[0].displayName").exists())
      .andExpect(jsonPath("$.Resources[0].active").exists())
      .andExpect(
          jsonPath("$.Resources[0].urn:indigo-dc:scim:schemas:IndigoUser.certificates").exists());


  }


  @Test
  public void testFilteringGivenNameEqNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().filters("givenName eq Madonna").build(),
          HttpStatus.NOT_FOUND)
      .andExpect(jsonPath("$.detail", equalTo(
          "the filter \"givenName,eq,Madonna\" produced no results as no data fulfilled the criteria.")));

  }

  @Test
  public void testFilteringGivenNameCoPositive() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().filters("givenName co tEs").build())
      .andExpect(jsonPath("$.totalResults", equalTo(250)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(100)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(100))))
      .andExpect(jsonPath("$.Resources[0].id").exists())
      .andExpect(jsonPath("$.Resources[0].name.givenName", containsStringIgnoringCase("tEs")))
      .andExpect(jsonPath("$.Resources[0].schemas").exists())
      .andExpect(jsonPath("$.Resources[0].userName").exists())
      .andExpect(jsonPath("$.Resources[0].emails").exists())
      .andExpect(jsonPath("$.Resources[0].displayName").exists())
      .andExpect(jsonPath("$.Resources[0].active").exists())
      .andExpect(jsonPath("$.Resources[1].id", equalTo("f2ce8cb2-a1db-4884-9ef0-d8842cc02b4a")))
      .andExpect(jsonPath("$.Resources[1].name.givenName", equalTo("Test-100")));

  }

  @Test
  public void testFilteringGivenNameCoNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().filters("givenName co xyz").build(), HttpStatus.NOT_FOUND)
      .andExpect(jsonPath("$.detail", equalTo(
          "the filter \"givenName,co,xyz\" produced no results as no data fulfilled the criteria.")));

  }


  @Test
  public void testFilteringFamilyNameEqPositive() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().filters("familyName eq User").build())
      .andExpect(jsonPath("$.totalResults", equalTo(250)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(100)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(100))))
      .andExpect(jsonPath("$.Resources[0].id").exists())
      .andExpect(jsonPath("$.Resources[0].name.givenName").exists())
      .andExpect(jsonPath("$.Resources[0].name.familyName", equalTo("User")))
      .andExpect(jsonPath("$.Resources[0].schemas").exists())
      .andExpect(jsonPath("$.Resources[0].userName").exists())
      .andExpect(jsonPath("$.Resources[0].emails").exists())
      .andExpect(jsonPath("$.Resources[0].displayName").exists())
      .andExpect(jsonPath("$.Resources[0].active").exists())
      .andExpect(
          jsonPath("$.Resources[0].urn:indigo-dc:scim:schemas:IndigoUser.certificates").exists())
      .andExpect(jsonPath("$.Resources[1].id").exists())
      .andExpect(jsonPath("$.Resources[1].name.familyName", equalTo("User")));
  }

  @Test
  public void testFilteringFamilyNameEqNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().filters("familyName eq Medici").build(),
          HttpStatus.NOT_FOUND)
      .andExpect(jsonPath("$.detail", equalTo(
          "the filter \"familyName,eq,Medici\" produced no results as no data fulfilled the criteria.")));

  }

  @Test
  public void testFilteringFamilyNameCoPositive() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().filters("familyName co uS").build())
      .andExpect(jsonPath("$.totalResults", equalTo(250)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(100)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(100))))
      .andExpect(jsonPath("$.Resources[0].id").exists())
      .andExpect(jsonPath("$.Resources[0].name.givenName").exists())
      .andExpect(jsonPath("$.Resources[0].name.familyName", containsStringIgnoringCase("uS")))
      .andExpect(jsonPath("$.Resources[0].schemas").exists())
      .andExpect(jsonPath("$.Resources[0].userName").exists())
      .andExpect(jsonPath("$.Resources[0].emails").exists())
      .andExpect(jsonPath("$.Resources[0].displayName").exists())
      .andExpect(jsonPath("$.Resources[0].active").exists())
      .andExpect(jsonPath("$.Resources[1].id").exists())
      .andExpect(jsonPath("$.Resources[1].name.familyName", containsStringIgnoringCase("uS")));
  }

  @Test
  public void testFilteringFamilyNameCoNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().filters("familyName co Ham").build(), HttpStatus.NOT_FOUND)
      .andExpect(jsonPath("$.detail", equalTo(
          "the filter \"familyName,co,Ham\" produced no results as no data fulfilled the criteria.")));

  }

  @Test
  public void testFilteringUsernameEqPositive() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().filters("Username eq admin").build())
      .andExpect(jsonPath("$.totalResults", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(1))))
      .andExpect(jsonPath("$.Resources[0].id", equalTo("73f16d93-2441-4a50-88ff-85360d78c6b5")))
      .andExpect(jsonPath("$.Resources[0].name.givenName", equalTo("Admin")))
      .andExpect(jsonPath("$.Resources[0].name.familyName", equalTo("User")))
      .andExpect(jsonPath("$.Resources[0].userName", equalTo("admin")))
      .andExpect(jsonPath("$.Resources[0].schemas").exists())
      .andExpect(jsonPath("$.Resources[0].emails").exists())
      .andExpect(jsonPath("$.Resources[0].displayName").exists())
      .andExpect(jsonPath("$.Resources[0].active").exists())
      .andExpect(
          jsonPath("$.Resources[0].urn:indigo-dc:scim:schemas:IndigoUser.certificates").exists());
  }

  @Test
  public void testFilteringUsernameEqNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().filters("username eq mrWorldWide").build(),
          HttpStatus.NOT_FOUND)
      .andExpect(jsonPath("$.detail", equalTo(
          "the filter \"username,eq,mrWorldWide\" produced no results as no data fulfilled the criteria.")));

  }


  @Test
  public void testFilteringUsernameCoPositive() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().filters("username co est").build())
      .andExpect(jsonPath("$.totalResults", equalTo(250)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(100)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(100))))
      .andExpect(jsonPath("$.Resources[0].id").exists())
      .andExpect(jsonPath("$.Resources[0].name.givenName").exists())
      .andExpect(jsonPath("$.Resources[0].name.familyName").exists())
      .andExpect(jsonPath("$.Resources[0].userName", containsStringIgnoringCase("est")))
      .andExpect(jsonPath("$.Resources[0].schemas").exists())
      .andExpect(jsonPath("$.Resources[0].emails").exists())
      .andExpect(jsonPath("$.Resources[0].displayName").exists())
      .andExpect(jsonPath("$.Resources[0].active").exists())
      .andExpect(jsonPath("$.Resources[1].id").exists())
      .andExpect(jsonPath("$.Resources[1].name.familyName").exists())
      .andExpect(jsonPath("$.Resources[1].userName", containsStringIgnoringCase("est")));
  }


  @Test
  public void testFilteringUsernameCoNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().filters("username co supreme").build(),
          HttpStatus.NOT_FOUND)
      .andExpect(jsonPath("$.detail", equalTo(
          "the filter \"username,co,supreme\" produced no results as no data fulfilled the criteria.")));

  }


  @Test
  public void testFilteringEmailsEqPositive() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().filters("emails eq 1_admin@iam.test").build())
      .andExpect(jsonPath("$.totalResults", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(1))))
      .andExpect(jsonPath("$.Resources[0].id", equalTo("73f16d93-2441-4a50-88ff-85360d78c6b5")))
      .andExpect(jsonPath("$.Resources[0].name.givenName", equalTo("Admin")))
      .andExpect(jsonPath("$.Resources[0].name.familyName", equalTo("User")))
      .andExpect(jsonPath("$.Resources[0].userName", equalTo("admin")))
      .andExpect(jsonPath("$.Resources[0].schemas").exists())
      .andExpect(jsonPath("$.Resources[0].emails[0].value", equalTo("1_admin@iam.test")))
      .andExpect(jsonPath("$.Resources[0].displayName").exists())
      .andExpect(jsonPath("$.Resources[0].active").exists())
      .andExpect(
          jsonPath("$.Resources[0].urn:indigo-dc:scim:schemas:IndigoUser.certificates").exists());
  }


  @Test
  public void testFilteringEmailsEqNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().filters("emails eq Bill.Nye@cern.ch").build(),
          HttpStatus.NOT_FOUND)
      .andExpect(jsonPath("$.detail", equalTo(
          "the filter \"emails,eq,Bill.Nye@cern.ch\" produced no results as no data fulfilled the criteria.")));

  }

  @Test
  public void testFilteringEmailsCoPositive() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().filters("emails co @iam.test").build())
      .andExpect(jsonPath("$.totalResults", equalTo(7)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(7)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(7))))
      .andExpect(jsonPath("$.Resources[0].id").exists())
      .andExpect(jsonPath("$.Resources[0].name.givenName").exists())
      .andExpect(jsonPath("$.Resources[0].name.familyName").exists())
      .andExpect(jsonPath("$.Resources[0].userName").exists())
      .andExpect(
          jsonPath("$.Resources[0].emails[0].value", containsStringIgnoringCase("@iam.test")))
      .andExpect(jsonPath("$.Resources[0].schemas").exists())
      .andExpect(jsonPath("$.Resources[0].emails").exists())
      .andExpect(jsonPath("$.Resources[0].displayName").exists())
      .andExpect(jsonPath("$.Resources[0].active").exists())
      .andExpect(jsonPath("$.Resources[1].id").exists())
      .andExpect(jsonPath("$.Resources[1].name.familyName").exists())
      .andExpect(jsonPath("$.Resources[1].userName").exists())
      .andExpect(
          jsonPath("$.Resources[1].emails[0].value", containsStringIgnoringCase("@iam.test")));
  }


  @Test
  public void testFilteringEmailsCoNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().filters("emails co @google.com").build(),
          HttpStatus.NOT_FOUND)
      .andExpect(jsonPath("$.detail", equalTo(
          "the filter \"emails,co,@google.com\" produced no results as no data fulfilled the criteria.")));

  }


  @Test
  public void testFilteringActivesEqPositive() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().filters("active eq true").build())
      .andExpect(jsonPath("$.totalResults", equalTo(255)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(100)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(100))))
      .andExpect(jsonPath("$.Resources[0].id").exists())
      .andExpect(jsonPath("$.Resources[0].name.givenName").exists())
      .andExpect(jsonPath("$.Resources[0].name.familyName").exists())
      .andExpect(jsonPath("$.Resources[0].userName").exists())
      .andExpect(jsonPath("$.Resources[0].active", equalTo(true)))
      .andExpect(jsonPath("$.Resources[0].schemas").exists())
      .andExpect(jsonPath("$.Resources[0].emails[0].value").exists())
      .andExpect(jsonPath("$.Resources[0].displayName").exists())
      .andExpect(
          jsonPath("$.Resources[0].urn:indigo-dc:scim:schemas:IndigoUser.certificates").exists())
      .andExpect(jsonPath("$.Resources[1].id").exists())
      .andExpect(jsonPath("$.Resources[1].active", equalTo(true)))

    ;
  }

  @Test
  public void testFilteringActiveEqNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().filters("active eq false").build(), HttpStatus.NOT_FOUND)
      .andExpect(jsonPath("$.detail", equalTo(
          "the filter \"active,eq,false\" produced no results as no data fulfilled the criteria.")));

  }

  @Test
  public void testFilteringActiveCoNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().filters("active co ue").build(), HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail",
          equalTo("the operator \"co\" can not be used with the given filtering attribute")));

  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testFilteringActivesEqPositive2() throws Exception {

    ScimUser user = ScimUser.builder("user_with_samlId")
      .buildEmail("test_user@test.org")
      .buildName("User", "With saml id Account")
      .buildSamlId("IdpID", "UserID")
      .active(false)
      .build();

    ScimUser createdUser = scimUtils.postUser(user);



    scimUtils.getUsers(ParamsBuilder.builder().filters("active eq false").build())
      .andExpect(jsonPath("$.totalResults", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(1))))
      .andExpect(jsonPath("$.Resources[0].id", equalTo(createdUser.getId())))
      .andExpect(jsonPath("$.Resources[0].name.givenName", equalTo("User")))
      .andExpect(jsonPath("$.Resources[0].name.familyName", equalTo("With saml id Account")))
      .andExpect(jsonPath("$.Resources[0].userName", equalTo("user_with_samlId")))
      .andExpect(jsonPath("$.Resources[0].active", equalTo(false)))
      .andExpect(jsonPath("$.Resources[0].emails[0].value", equalTo("test_user@test.org")))
      .andExpect(jsonPath("$.Resources[0].displayName").exists())
      .andExpect(jsonPath("$.Resources[0].urn:indigo-dc:scim:schemas:IndigoUser.samlIds[0].userId",
          equalTo("UserID")))
      .andExpect(jsonPath("$.Resources[0].urn:indigo-dc:scim:schemas:IndigoUser.samlIds[0].idpId",
          equalTo("IdpID")));
  }


  @Test
  public void testFilteringAttributesCountIndexPosititve() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder()
        .count(2)
        .startIndex(2)
        .attributes("userName,emails," + INDIGO_USER_SCHEMA)
        .filters("active eq true")
        .build())
      .andExpect(jsonPath("$.totalResults", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(2)))
      .andExpect(jsonPath("$.startIndex", equalTo(2)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(2))))
      .andExpect(jsonPath("$.Resources[0].id").exists())
      .andExpect(jsonPath("$.Resources[0].schemas").exists())
      .andExpect(jsonPath("$.Resources[0].userName").exists())
      .andExpect(jsonPath("$.Resources[0].emails").exists())
      .andExpect(jsonPath("$.Resources[0].displayName").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].nickName").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].profileUrl").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].locale").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].timezone").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].active").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].title").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].addresses").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].certificates").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].groups").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].urn:indigo-dc:scim:schemas:IndigoUser").exists());

  }


  @Test
  public void testFilteringAttributesCountIndexNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder()
        .count(2)
        .startIndex(2)
        .attributes("userName,emails," + INDIGO_USER_SCHEMA)
        .filters("SomethingWrong")
        .build(), HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail",
          equalTo("the filter \"SomethingWrong\" does not fulfill the filtering convention")));

  }


  @Test
  public void testFilteringNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().count(2).filters(" ").build(), HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail",
          equalTo("the filter \" \" does not fulfill the filtering convention")));

  }


  @Test
  public void testFilteringNegative2() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().count(2).filters("Something wrong").build(),
          HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail",
          equalTo("the filter \"Something wrong\" does not fulfill the filtering convention")));

  }


  @Test
  public void testFilteringNegative3() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().count(2).filters("givenName wrong true").build(),
          HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", equalTo(
          "the filter \"givenName wrong true\" does not fulfill the filtering convention")));

  }


  @Test
  public void testFilteringNegative4() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().count(2).filters("active eq correct").build(),
          HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail",
          equalTo("the value \"correct\" does not fulfill the filtering convention")));

  }

  @Test
  public void testFilteringNegative5() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().count(2).filters("eq eq something").build(),
          HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail",
          equalTo("the filter \"eq eq something\" does not fulfill the filtering convention")));

  }

  @Test
  public void testFilteringEvalutationNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().count(2).filters("eq eq something").build(),
          HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail",
          equalTo("the filter \"eq eq something\" does not fulfill the filtering convention")));

  }



  @Test
  public void testFilteringParseFiltersNegative() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder().filters("eqeqcoco co something").build(),
          HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", equalTo(
          "the filter \"eqeqcoco co something\" does not fulfill the filtering convention")));

  }



}
