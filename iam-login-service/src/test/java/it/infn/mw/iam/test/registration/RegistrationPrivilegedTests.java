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
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.CONFIRMED;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.NEW;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.REJECTED;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamRegistrationRequestRepository;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.registration.RegistrationRequestService;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class RegistrationPrivilegedTests {

  @Autowired
  private PersistentUUIDTokenGenerator generator;

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private RegistrationRequestService registrationService;

  @Autowired
  private IamRegistrationRequestRepository requestRepo;

  @Autowired
  private IamAccountRepository repo;

  @Before
  public void setup() {
    requestRepo.deleteAll();
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    requestRepo.deleteAll();
    mockOAuth2Filter.cleanupSecurityContext();
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
    request.setPassword("password");

    // @formatter:off
    String response = mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(request)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    return objectMapper.readValue(response, RegistrationRequestDto.class);
  }

  private void confirmRegistrationRequest(String confirmationKey) throws Exception {
    // @formatter:off
    mvc.perform(get("/registration/confirm/{token}", confirmationKey))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(CONFIRMED.name())));
    // @formatter:on
  }

  protected RegistrationRequestDto approveRequest(String uuid) throws Exception {
    String response = mvc
      .perform(post("/registration/approve/{uuid}", uuid)
        .with(SecurityMockMvcRequestPostProcessors.user("admin").roles("ADMIN", "USER")))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on
    return objectMapper.readValue(response, RegistrationRequestDto.class);
  }



  @Test
  @WithMockOAuthUser(clientId = "registration-client", scopes = {"registration:read"})
  public void testListNewRequests() throws Exception {

    createRegistrationRequest("test_list_new");

    // @formatter:off
    mvc.perform(get("/registration/list")
        .param("status", NEW.name()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$", hasSize(1)));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "registration-client",
      scopes = {"registration:read", "registration:write"})
  public void testListPendingRequest() throws Exception {

    createRegistrationRequest("test_1");
    createRegistrationRequest("test_2");

    String confirmationKey = generator.getLastToken();
    confirmRegistrationRequest(confirmationKey);

    RegistrationRequestDto reg3 = createRegistrationRequest("test_3");
    approveRequest(reg3.getUuid());

    // @formatter:off
    // 1 NEW, 1 CONFIRMED, 1 APPROVED -> expect 2 elements returned
    mvc.perform(get("/registration/list/pending"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$", hasSize(2)));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "registration-client", scopes = {"registration:read"})
  public void testListAllRequests() throws Exception {

    createRegistrationRequest("test_list_1");
    createRegistrationRequest("test_list_2");

    String token = generator.getLastToken();
    assertNotNull(token);

    confirmRegistrationRequest(token);

    // @formatter:off
    mvc.perform(get("/registration/list"))
     .andExpect(status().isOk())
     .andExpect(jsonPath("$", hasSize(2)));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "registration-client", scopes = {"registration:write"})
  public void testApproveRequest() throws Exception {

    RegistrationRequestDto reg = createRegistrationRequest("test_approve");
    assertNotNull(reg);

    String token = generator.getLastToken();
    assertNotNull(token);

    confirmRegistrationRequest(token);

    // approve it
    // @formatter:off
    mvc.perform(post("/registration/approve/{uuid}", reg.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(APPROVED.name())))
      .andExpect(jsonPath("$.uuid", equalTo(reg.getUuid())));
    // @formatter:on

    IamAccount account = repo.findByUsername("test_approve")
      .orElseThrow(assertionError("Expected account not found"));
    assertThat(account.getEndTime(), nullValue());

  }

  @Test
  @WithMockOAuthUser(clientId = "registration-client",
      scopes = {"scim:write", "scim:read", "registration:write"})
  public void testRejectRequest() throws Exception {

    RegistrationRequestDto reg = createRegistrationRequest("test_reject");
    assertNotNull(reg);

    String token = generator.getLastToken();
    assertNotNull(token);

    confirmRegistrationRequest(token);

    // @formatter:off
    // reject it
    mvc.perform(post("/registration/reject/{uuid}", reg.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(REJECTED.name())))
      .andExpect(jsonPath("$.uuid", equalTo(reg.getUuid())));
    // @formatter:on

    // Reject delete user: verify user not found
    // @formatter:off
    mvc.perform(get("/scim/Users/{uuid}", reg.getAccountId())
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isNotFound());
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "registration-client", scopes = {"registration:write"})
  public void testApproveRequestNotConfirmed() throws Exception {

    // create new request
    RegistrationRequestDto reg = createRegistrationRequest("test_approve_not_confirmed");
    assertNotNull(reg);

    // @formatter:off
    // approve it without confirm
    mvc.perform(post("/registration/approve/{uuid}", reg.getUuid(), APPROVED.name()))
      .andExpect(status().isOk());
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "registration-client", scopes = {"registration:write"})
  public void testConfirmAfterApprovation() throws Exception {

    RegistrationRequestDto reg = createRegistrationRequest("test_confirm_after_approve");
    assertNotNull(reg);
    String confirmationKey = generator.getLastToken();

    approveRequest(reg.getUuid());

    // @formatter:off
    mvc.perform(get("/registration/confirm/{token}", confirmationKey))
      .andExpect(status().isNotFound());
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "registration-client", scopes = {"registration:write"})
  public void confirmAlreadyConfirmedRequest() throws Exception {
    // create new request
    RegistrationRequestDto reg = createRegistrationRequest("test_multiple_confirm");
    assertNotNull(reg);

    String confirmationKey = generator.getLastToken();
    approveRequest(reg.getUuid());

    mvc.perform(get("/registration/confirm/{token}", confirmationKey))
      .andExpect(status().isNotFound());

  }

  @Test(expected = IllegalArgumentException.class)
  @WithMockOAuthUser(clientId = "registration-client", scopes = {"registration:write"})
  public void approveAlreadyManagedRequest() throws Exception {

    // create new request
    RegistrationRequestDto reg = createRegistrationRequest("test_multiple_approve");
    assertNotNull(reg);

    // first approval works fine
    registrationService.approveRequest(reg.getUuid());

    // second one raises exception, due to unallowed transition
    registrationService.approveRequest(reg.getUuid());
  }
}
