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

import static it.infn.mw.iam.core.IamRegistrationRequestStatus.APPROVED;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.CONFIRMED;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.api.aup.AupTestSupport;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class RegistrationUnprivilegedTests extends AupTestSupport {

  @Autowired
  private WebApplicationContext context;

  @Autowired
  private PersistentUUIDTokenGenerator generator;

  @Autowired
  private IamAupRepository aupRepo;

  @Autowired
  private IamAupSignatureRepository aupSignatureRepo;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private ObjectMapper objectMapper;

  private MockMvc mvc;

  @Before
  public void setup() {
    mvc =
        MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysDo(log()).build();
  }

  @Test
  public void testCreateRequest() throws Exception {

    RegistrationRequestDto reg = createRegistrationRequest("test_create");

    assertNotNull(reg);
    assertThat(reg.getUsername(), equalTo("test_create"));
    assertThat(reg.getGivenname(), equalTo("Test"));
    assertThat(reg.getFamilyname(), equalTo("User"));
    assertThat(reg.getEmail(), equalTo("test_create@example.org"));
    assertThat(reg.getNotes(), equalTo("Some short notes..."));
  }

  @Test
  public void createRequestCreatesAupSignatureIfAupIsDefined() throws Exception {

    IamAup aup = buildDefaultAup();
    aupRepo.save(aup);

    RegistrationRequestDto reg = createRegistrationRequest("test_create");

    assertThat(reg.getUsername(), equalTo("test_create"));
    assertThat(reg.getGivenname(), equalTo("Test"));
    assertThat(reg.getFamilyname(), equalTo("User"));
    assertThat(reg.getEmail(), equalTo("test_create@example.org"));
    assertThat(reg.getNotes(), equalTo("Some short notes..."));

    IamAccount account = accountRepo.findByUuid(reg.getAccountId())
      .orElseThrow(() -> new AssertionError("Expected account not found!"));

    aupSignatureRepo.findSignatureForAccount(account)
      .orElseThrow(() -> new AssertionError("Expected signature not found!"));
  }


  @Test
  public void testConfirmRequest() throws Exception {

    createRegistrationRequest("test_confirm");
    String token = generator.getLastToken();
    assertNotNull(token);
    confirmRegistrationRequest(token);
  }

  @Test
  public void testListRequestsUnauthorized() throws Exception {

    // @formatter:off
    mvc.perform(get("/registration/list")
        .with(authentication(anonymousAuthenticationToken())))
      .andExpect(status().isUnauthorized());
    // @formatter:on
  }

  @Test
  public void testConfirmRequestFailureWithWrongToken() throws Exception {

    createRegistrationRequest("test_confirm_fail");
    String badToken = "abcdefghilmnopqrstuvz";

    // @formatter:off
    mvc.perform(get("/registration/confirm/{token}", badToken))
      .andExpect(status().isNotFound());
    // @formatter:on
  }

  @Test
  public void testApproveRequestUnauthorized() throws Exception {

    RegistrationRequestDto reg = createRegistrationRequest("test_approve_unauth");
    assertNotNull(reg);

    String token = generator.getLastToken();
    assertNotNull(token);

    confirmRegistrationRequest(token);

    // @formatter:off
    mvc.perform(post("/registration/{uuid}/{decision}", reg.getUuid(), APPROVED.name())
        .with(authentication(anonymousAuthenticationToken())))
      .andExpect(status().isUnauthorized());
    // @formatter:on
  }

  @Test
  public void testUsernameAvailable() throws Exception {
    String username = "tester";
    // @formatter:off
    mvc.perform(get("/registration/username-available/{username}", username))
      .andExpect(status().isOk())
      .andExpect(content().string("true"));
    // @formatter:on
  }

  @Test
  public void testUsernameAlreadyTaken() throws Exception {
    String username = "admin";
    // @formatter:off
    mvc.perform(get("/registration/username-available/{username}", username))
      .andExpect(status().isOk())
      .andExpect(content().string("false"));
    // @formatter:on
  }

  @Test
  public void testCreateRequestWithoutNotes() throws Exception {

    String username = "user_with_empty_notes";
    String email = username + "@example.org";

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setPassword("password");

    // @formatter:off
    mvc.perform(post("/registration/create")
        .contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest());
    // @formatter:on
  }

  @Test
  public void testCreateRequestBlankNotes() throws Exception {

    String username = "user_with_empty_notes";
    String email = username + "@example.org";

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setPassword("password");
    request.setNotes(" ");

    // @formatter:off
    mvc.perform(post("/registration/create")
        .contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest());
    // @formatter:on
  }

  @Test
  public void testEmailAvailableEndpoint() throws Exception {
    mvc.perform(get("/registration/email-available/email@example.org"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").value(true));

    mvc.perform(get("/registration/email-available/test@iam.test"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").value(false));
  }


  private Authentication anonymousAuthenticationToken() {
    return new AnonymousAuthenticationToken("key", "anonymous",
        AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
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


}
