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
package it.infn.mw.iam.test.registration;

import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.APPROVED;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.NEW;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.REJECTED;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.function.Supplier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamRegistrationRequestRepository;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.registration.RegistrationRequestService;
import it.infn.mw.iam.test.util.oauth.OAuthTokenTestUtils;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class RegistrationPrivilegedTests {

  static final String REGISTRATION_CLIENT_ID = "registration-client";
  static final String REGISTRATION_CLIENT_SECRET = "secret";

  @Autowired
  private PersistentUUIDTokenGenerator generator;

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private RegistrationRequestService registrationService;

  @Autowired
  private IamRegistrationRequestRepository requestRepo;

  @Autowired
  private IamAccountRepository repo;

  @AfterEach
  void teardown() {
    requestRepo.deleteAll();
  }

  private String registrationToken(String... scopes) throws Exception {
    return OAuthTokenTestUtils.clientCredentialsToken(mvc, objectMapper, REGISTRATION_CLIENT_ID,
        REGISTRATION_CLIENT_SECRET, scopes);
  }

  private Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

  private RegistrationRequestDto createRegistrationRequest(String username) throws Exception {

    String email = username + "@example.org";
    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setNotes("Some short notes...");

    // @formatter:off
    String response = mvc
      .perform(post("/registration/create").with(csrf().asHeader()).contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(request)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    return objectMapper.readValue(response, RegistrationRequestDto.class);
  }

  private void confirmRegistrationRequest(String confirmationKey) throws Exception {
    mvc
      .perform(post("/registration/verify").with(csrf().asHeader())
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", confirmationKey))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("verificationSuccess"));
  }

  protected RegistrationRequestDto approveRequest(String uuid, String accessToken)
      throws Exception {

    String response = mvc
      .perform(
          post("/registration/approve/{uuid}", uuid).header(AUTHORIZATION, "Bearer " + accessToken))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    return objectMapper.readValue(response, RegistrationRequestDto.class);
  }

  @Test
  void testListNewRequests() throws Exception {

    String accessToken = registrationToken("registration:read");

    createRegistrationRequest("test_list_new");

    mvc
      .perform(get("/registration/list").header(AUTHORIZATION, "Bearer " + accessToken)
        .param("status", NEW.name()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$", hasSize(1)));
  }

  @Test
  void testListPendingRequest() throws Exception {

    String accessToken = registrationToken("registration:read", "registration:write");

    createRegistrationRequest("test_1");
    createRegistrationRequest("test_2");

    String confirmationKey = generator.getLastToken();
    confirmRegistrationRequest(confirmationKey);

    RegistrationRequestDto reg3 = createRegistrationRequest("test_3");
    approveRequest(reg3.getUuid(), accessToken);

    mvc.perform(get("/registration/list/pending").header(AUTHORIZATION, "Bearer " + accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$", hasSize(2)));
  }

  @Test
  void testListAllRequests() throws Exception {

    String accessToken = registrationToken("registration:read");

    createRegistrationRequest("test_list_1");
    createRegistrationRequest("test_list_2");

    String confirmationKey = generator.getLastToken();
    assertNotNull(confirmationKey);

    confirmRegistrationRequest(confirmationKey);

    mvc.perform(get("/registration/list").header(AUTHORIZATION, "Bearer " + accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$", hasSize(2)));
  }

  @Test
  void testApproveRequest() throws Exception {

    String accessToken = registrationToken("registration:write");

    RegistrationRequestDto reg = createRegistrationRequest("test_approve");
    assertNotNull(reg);

    String confirmationKey = generator.getLastToken();
    assertNotNull(confirmationKey);

    confirmRegistrationRequest(confirmationKey);

    mvc
      .perform(post("/registration/approve/{uuid}", reg.getUuid()).header(AUTHORIZATION,
          "Bearer " + accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(APPROVED.name())))
      .andExpect(jsonPath("$.uuid", equalTo(reg.getUuid())));

    IamAccount account = repo.findByUsername("test_approve")
      .orElseThrow(assertionError("Expected account not found"));

    assertThat(account.getEndTime(), nullValue());
  }

  @Test
  void testRejectRequest() throws Exception {

    String accessToken = registrationToken("scim:write", "scim:read", "registration:write");

    RegistrationRequestDto reg = createRegistrationRequest("test_reject");
    assertNotNull(reg);

    String confirmationKey = generator.getLastToken();
    assertNotNull(confirmationKey);

    confirmRegistrationRequest(confirmationKey);

    mvc
      .perform(post("/registration/reject/{uuid}", reg.getUuid()).header(AUTHORIZATION,
          "Bearer " + accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(REJECTED.name())))
      .andExpect(jsonPath("$.uuid", equalTo(reg.getUuid())));

    mvc.perform(
        get("/scim/Users/{uuid}", reg.getAccountId()).header(AUTHORIZATION, "Bearer " + accessToken)
          .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isNotFound());
  }

  @Test
  void testApproveRequestNotConfirmed() throws Exception {

    String accessToken = registrationToken("registration:write");

    RegistrationRequestDto reg = createRegistrationRequest("test_approve_not_confirmed");
    assertNotNull(reg);

    mvc.perform(post("/registration/approve/{uuid}", reg.getUuid()).header(AUTHORIZATION,
        "Bearer " + accessToken))
      .andExpect(status().isOk());
  }

  @Test
  void testConfirmAfterApprovation() throws Exception {

    String accessToken = registrationToken("registration:write");

    RegistrationRequestDto reg = createRegistrationRequest("test_confirm_after_approve");
    assertNotNull(reg);

    String confirmationKey = generator.getLastToken();
    assertNotNull(confirmationKey);

    approveRequest(reg.getUuid(), accessToken);

    mvc
      .perform(post("/registration/verify").with(csrf().asHeader())
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", confirmationKey))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("verificationFailure"));
  }

  @Test
  void confirmAlreadyConfirmedRequest() throws Exception {

    RegistrationRequestDto reg = createRegistrationRequest("test_multiple_confirm");
    assertNotNull(reg);

    String confirmationKey = generator.getLastToken();
    assertNotNull(confirmationKey);

    confirmRegistrationRequest(confirmationKey);

    mvc
      .perform(post("/registration/verify").with(csrf().asHeader())
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", confirmationKey))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("verificationFailure"));
  }

  @Test
  void approveAlreadyManagedRequest() throws Exception {

    String accessToken = registrationToken("registration:write");

    RegistrationRequestDto reg = createRegistrationRequest("test_multiple_approve");
    assertNotNull(reg);

    String regUuid = reg.getUuid();

    approveRequest(regUuid, accessToken);

    assertThrows(IllegalArgumentException.class, () -> registrationService.approveRequest(regUuid));
  }
}
