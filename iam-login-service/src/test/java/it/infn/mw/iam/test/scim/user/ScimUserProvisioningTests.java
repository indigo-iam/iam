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

import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CONTENT_TYPE;
import static it.infn.mw.iam.test.scim.ScimUtils.buildUser;
import static it.infn.mw.iam.test.scim.ScimUtils.buildUserWithUUID;
import static it.infn.mw.iam.test.scim.ScimUtils.getUserLocation;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimEmail.ScimEmailType;
import it.infn.mw.iam.api.scim.model.ScimGroupRef;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.test.scim.ScimUtils;
import it.infn.mw.iam.test.util.oauth.OAuthTokenTestUtils;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class ScimUserProvisioningTests {

  @Autowired
  MockMvc mvc;

  @Autowired
  ObjectMapper mapper;

  @InjectMocks
  ScimUserProvisioning scimUserProvisioning;

  String scimAccessToken;

  @BeforeEach
  void setup() {
    scimAccessToken = null;
  }

  private String token(String... scopes) throws Exception {
    return OAuthTokenTestUtils.clientCredentialsToken(mvc, mapper, ScimUtils.SCIM_CLIENT_ID,
        ScimUtils.SCIM_CLIENT_SECRET, scopes);
  }

  private ResultActions performScim(MockHttpServletRequestBuilder request) throws Exception {

    if (scimAccessToken == null) {
      scimAccessToken = token(ScimUtils.SCIM_READ_SCOPE, ScimUtils.SCIM_WRITE_SCOPE);
    }

    return mvc.perform(request.header(HttpHeaders.AUTHORIZATION, "Bearer " + scimAccessToken));
  }

  private ResultActions getUser(String uuid, HttpStatus expectedStatus) throws Exception {

    return performScim(
        get(ScimUtils.getUsersLocation() + "/{uuid}", uuid).accept(SCIM_CONTENT_TYPE))
          .andExpect(status().is(expectedStatus.value()));
  }

  private ScimUser getUser(String uuid) throws Exception {

    String response = getUser(uuid, HttpStatus.OK).andReturn().getResponse().getContentAsString();

    return mapper.readValue(response, ScimUser.class);
  }

  private ScimUser postUser(ScimUser user) throws Exception {

    String response = performScim(post(ScimUtils.getUsersLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(mapper.writeValueAsBytes(user))).andExpect(status().isCreated())
        .andReturn()
        .getResponse()
        .getContentAsString();

    return mapper.readValue(response, ScimUser.class);
  }

  private ScimUser putUser(String uuid, ScimUser user) throws Exception {

    String response = performScim(
        put(ScimUtils.getUsersLocation() + "/{uuid}", uuid).contentType(SCIM_CONTENT_TYPE)
          .content(mapper.writeValueAsBytes(user))).andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();

    return mapper.readValue(response, ScimUser.class);
  }

  private ResultActions deleteUser(String uuid) throws Exception {
    return performScim(delete(ScimUtils.getUsersLocation() + "/{uuid}", uuid));
  }

  private String getRandomUUid() {
    return UUID.randomUUID().toString();
  }

  @Test
  void testGetUserNotFoundResponse() throws Exception {

    scimAccessToken = token(ScimUtils.SCIM_READ_SCOPE);

    String randomUuid = getRandomUUid();

    getUser(randomUuid, HttpStatus.NOT_FOUND).andExpect(jsonPath("$.status", equalTo("404")))
      .andExpect(jsonPath("$.detail", equalTo("No user mapped to id '" + randomUuid + "'")));
  }

  @Test
  void testUpdateUserNotFoundResponse() throws Exception {

    String randomUuid = getRandomUUid();
    ScimUser user =
        ScimUtils.buildUser("john_lennon", "lennon@email.test", "John", "Lennon").build();

    performScim(put(ScimUtils.getUsersLocation() + "/" + randomUuid)
        .content(mapper.writeValueAsBytes(user))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.status", equalTo("404")))
      .andExpect(jsonPath("$.detail", equalTo("No user mapped to id '" + randomUuid + "'")));
  }

  @Test
  void testExistingUserAccess() throws Exception {

    scimAccessToken = token(ScimUtils.SCIM_READ_SCOPE);

    // Some existing user as defined in the test db
    String uuid = "80e5fb8d-b7c8-451a-89ba-346ae278a66f";

    ScimGroupRef productionRef = ScimGroupRef.builder()
      .display("Production")
      .ref("http://localhost:8080/scim/Groups/c617d586-54e6-411d-8e38-64967798fa8a")
      .value("c617d586-54e6-411d-8e38-64967798fa8a")
      .build();

    ScimGroupRef analysisRef = ScimGroupRef.builder()
      .display("Analysis")
      .ref("http://localhost:8080/scim/Groups/6a384bcd-d4b3-4b7f-a2fe-7d897ada0dd1")
      .value("6a384bcd-d4b3-4b7f-a2fe-7d897ada0dd1")
      .build();

    ScimGroupRef optionalRef = ScimGroupRef.builder()
      .display("Optional")
      .ref("http://localhost:8080/scim/Groups/31d9230c-90ae-4457-a990-0c443ab4aacc")
      .value("31d9230c-90ae-4457-a990-0c443ab4aacc")
      .build();

    ScimUser user = getUser(uuid);

    assertThat(user.getId(), equalTo(uuid));
    assertThat(user.getUserName(), equalTo("test"));
    assertThat(user.getDisplayName(), equalTo("test"));
    assertThat(user.getActive(), equalTo(true));
    assertThat(user.getName().getFamilyName(), equalTo("User"));
    assertThat(user.getName().getGivenName(), equalTo("Test"));
    assertThat(user.getName().getFormatted(), equalTo("Test User"));
    assertThat(user.getMeta().getResourceType(), equalTo("User"));
    assertThat(user.getMeta().getLocation(),
        equalTo("http://localhost:8080" + getUserLocation(uuid)));
    assertThat(user.getEmails(), hasSize(equalTo(1)));
    assertThat(user.getEmails().get(0).getValue(), equalTo("test@iam.test"));
    assertThat(user.getEmails().get(0).getType(), equalTo(ScimEmailType.work));
    assertThat(user.getEmails().get(0).getPrimary(), equalTo(true));
    assertThat(user.getGroups(), hasSize(equalTo(3)));
    assertThat(user.getGroups(), hasItems(analysisRef, productionRef, optionalRef));
    assertThat(user.getIndigoUser().getOidcIds(), hasSize(greaterThan(0)));
    assertThat(user.getIndigoUser().getOidcIds().get(0).getIssuer(),
        equalTo("https://accounts.google.com"));
    assertThat(user.getIndigoUser().getOidcIds().get(0).getSubject(),
        equalTo("105440632287425289613"));
  }

  @Test
  void testEmptyUsernameValidationError() throws Exception {

    ScimUser user = buildUser("", "test@email.test", "Paul", "McCartney").build();

    performScim(post(ScimUtils.getUsersLocation()).content(mapper.writeValueAsBytes(user))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.status", equalTo("400")))
      .andExpect(jsonPath("$.detail", containsString("scimUser.userName : must not be blank")));
  }

  @Test
  void testEmptyEmailValidationError() throws Exception {

    ScimUser user = ScimUser.builder("paul").buildName("Paul", "McCartney").build();

    performScim(post(ScimUtils.getUsersLocation()).content(mapper.writeValueAsBytes(user))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.status", equalTo("400")))
      .andExpect(jsonPath("$.detail", containsString("scimUser.emails : must not be empty")));
  }

  @Test
  void testInvalidEmailValidationError() throws Exception {

    ScimUser user = buildUser("paul", "this_is_not_an_email", "Paul", "McCartney").build();

    performScim(post(ScimUtils.getUsersLocation()).content(mapper.writeValueAsBytes(user))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.status", equalTo("400")))
      .andExpect(jsonPath("$.detail", containsString("Please provide a valid email address")));
  }

  @Test
  void testUserUpdateChangeUsername() throws Exception {

    ScimUser user = buildUser("john_lennon", "lennon@email.test", "John", "Lennon").build();

    ScimUser createdUser = postUser(user);
    long creationTimeMs = createdUser.getMeta().getCreated().getTime();

    ScimUser userWithUpdates =
        buildUserWithUUID(createdUser.getId(), "j.lennon", user.getEmails().get(0).getValue(),
            user.getName().getGivenName(), user.getName().getFamilyName()).build();

    ScimUser updatedUser = putUser(userWithUpdates.getId(), userWithUpdates);

    assertThat(updatedUser.getUserName(), equalTo(userWithUpdates.getUserName()));
    long returnedTimeMs = updatedUser.getMeta().getCreated().getTime();

    // We need to do this since milliseconds are truncated for the creation time in MySQL
    assertThat(Math.abs(returnedTimeMs - creationTimeMs), Matchers.lessThan(Long.valueOf(1000)));
  }

  @Test
  void testUpdateUserValidation() throws Exception {

    ScimUser user = buildUser("john_lennon", "lennon@email.test", "John", "Lennon").build();

    postUser(user);

    ScimUser userWithUpdates = ScimUser.builder("j.lennon").id(user.getId()).active(true).build();

    performScim(put(ScimUtils.getUsersLocation() + "/" + user.getId())
        .content(mapper.writeValueAsBytes(userWithUpdates))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.detail", containsString("scimUser.emails : must not be empty")));
  }

  @Test
  void testNonExistentUserDeletionReturns404() throws Exception {

    deleteUser(getRandomUUid()).andExpect(status().isNotFound());
  }

  @Test
  void testReplaceUserWithAlreadyUsedUsername() throws Exception {

    ScimUser lennon = buildUser("john_lennon", "lennon@email.test", "John", "Lennon").build();

    ScimUser lennonCreationResult = postUser(lennon);

    ScimUser mccartney =
        buildUser("paul_mccartney", "test@email.test", "Paul", "McCartney").build();

    postUser(mccartney);

    ScimUser lennonWantsToBeMcCartney = buildUserWithUUID(lennonCreationResult.getId(),
        mccartney.getUserName(), mccartney.getEmails().get(0).getValue(),
        mccartney.getName().getGivenName(), mccartney.getName().getFamilyName()).build();


    performScim(put(ScimUtils.getUsersLocation() + "/" + lennonCreationResult.getId())
        .content(mapper.writeValueAsBytes(lennonWantsToBeMcCartney))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isConflict())
      .andExpect(jsonPath("$.detail",
          containsString("username paul_mccartney already assigned to another user")));

  }

  @Test
  void testUniqueUsernameCreationCheck() throws Exception {

    ScimUser user1 = buildUser("john_lennon", "lennon@email.test", "John", "Lennon").build();
    ScimUser user2 =
        buildUser("john_lennon", "another_lennon@email.test", "John", "Lennon").build();

    postUser(user1);

    performScim(post(ScimUtils.getUsersLocation()).content(mapper.writeValueAsBytes(user2))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isConflict())
      .andExpect(jsonPath("$.detail",
          containsString("A user with username 'john_lennon' already exists")));


  }

  @Test
  void testEmailIsNotAlreadyLinkedOnCreate() throws Exception {

    ScimUser user0 =
        buildUser("test_same_email_0", "same_email@test.org", "Test", "Same Email 0").build();
    ScimUser user1 =
        buildUser("test_same_email_1", "same_email@test.org", "Test", "Same Email 1").build();

    user0 = postUser(user0);

    performScim(post(ScimUtils.getUsersLocation()).content(mapper.writeValueAsBytes(user1))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isConflict())
      .andExpect(jsonPath("$.detail",
          containsString("A user linked with email 'same_email@test.org' already exists")));

  }

  @Test
  void testEmailIsNotAlreadyLinkedOnUpdate() throws Exception {

    ScimUser user0 = buildUser("user0", "user0@test.org", "Test", "User 0").build();
    ScimUser user1 = buildUser("user1", "user1@test.org", "Test", "User 1").build();

    user0 = postUser(user0);
    user1 = postUser(user1);

    ScimUser updatedUser0 =
        buildUserWithUUID(user0.getId(), "user0", "user1@test.org", "Test", "User 0").build();

    performScim(put(ScimUtils.getUsersLocation() + "/" + user0.getId())
        .content(mapper.writeValueAsBytes(updatedUser0))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isConflict())
      .andExpect(jsonPath("$.detail",
          containsString("email user1@test.org already assigned to another user")));

  }

  @Test
  void userListFilterReference() {

    Exception notimplemented =
        assertThrows(UnsupportedOperationException.class, () -> scimUserProvisioning.list(null));

    assertTrue(notimplemented.getMessage().contains("Unsupported list method"));

  }
}
