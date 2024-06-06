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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
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
import it.infn.mw.iam.config.IamProperties.ExternalAuthAttributeSectionBehaviour;
import it.infn.mw.iam.config.IamProperties.RegistrationFieldProperties;
import it.infn.mw.iam.config.IamProperties.RegistrationProperties;
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

  @MockBean
  private RegistrationProperties registrationProperties;

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

    aupSignatureRepo.findSignatureForAccount(aup, account)
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

    mvc.perform(get("/registration/list").with(authentication(anonymousAuthenticationToken())))
      .andExpect(status().isUnauthorized());
  }

  @Test
  public void testConfirmRequestFailureWithWrongToken() throws Exception {

    createRegistrationRequest("test_confirm_fail");
    String badToken = "abcdefghilmnopqrstuvz";

    mvc
      .perform(post("/registration/verify").content("token=" + badToken)
        .contentType(APPLICATION_FORM_URLENCODED))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("verificationFailure"));
  }

  @Test
  public void testApproveRequestUnauthorized() throws Exception {

    RegistrationRequestDto reg = createRegistrationRequest("test_approve_unauth");
    assertNotNull(reg);

    String token = generator.getLastToken();
    assertNotNull(token);

    mvc.perform(head("/registration/verify/" + token)).andExpect(status().isOk());

    confirmRegistrationRequest(token);

    mvc.perform(post("/registration/{uuid}/{decision}", reg.getUuid(), APPROVED.name())
      .with(authentication(anonymousAuthenticationToken()))).andExpect(status().isUnauthorized());
  }

  @Test
  public void testUsernameAvailable() throws Exception {
    String username = "tester";
    mvc.perform(get("/registration/username-available/{username}", username))
      .andExpect(status().isOk())
      .andExpect(content().string("true"));
  }

  @Test
  public void testUsernameAlreadyTaken() throws Exception {
    String username = "admin";
    mvc.perform(get("/registration/username-available/{username}", username))
      .andExpect(status().isOk())
      .andExpect(content().string("false"));
  }

  @Test
  public void testCreateRequestWithMandatoryNotesField() throws Exception {

    String username = "user_with_empty_notes";
    String email = username + "@example.org";

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setPassword("password");
    // `Notes` field is mandatory
    request.setNotes("Notes is mandatory");

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(request)))
      .andExpect(status().isOk());
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

  @Test
  public void testVerifySucess() throws Exception {
    RegistrationRequestDto reg = createRegistrationRequest("test_approve_unauth");
    assertNotNull(reg);

    String token = generator.getLastToken();
    assertNotNull(token);

    // @formatter:off
    mvc.perform(get("/registration/verify/{token}", token))
      .andExpect(status().isOk());
    // @formatter:on
  }

  @Test
  public void testVerifyElseCase() throws Exception {
    String token = "noID";

    // @formatter:off
    mvc.perform(get("/registration/verify/{token}", token))
      .andExpect(status().isOk())
      .andExpect(model().attribute("verificationFailure", true));
    // @formatter:on
  }

  @Test
  public void testInsufficientAuth() throws Exception {
    // @formatter:off
    mvc.perform(get("/registration/insufficient-aut"))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", equalTo("unauthorized")));
    // @formatter:on
  }

  @Test
  public void testRegistrationConfig() throws Exception {
    Map<String, RegistrationFieldProperties> fieldAttribute = new HashMap<>();
    RegistrationFieldProperties notesProperties = new RegistrationFieldProperties();
    notesProperties.setReadOnly(true);
    notesProperties.setExternalAuthAttribute("notes");
    notesProperties.setFieldBehaviour(ExternalAuthAttributeSectionBehaviour.MANDATORY);
    fieldAttribute.put("notes", notesProperties);

    when(registrationProperties.getFields()).thenReturn(fieldAttribute);

    // @formatter:off
    mvc.perform(get("/registration/config"))
      .andExpect(status().isOk())
      .andExpect(content().json("{}"));
    // @formatter:on
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

    String response = mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(request)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    return objectMapper.readValue(response, RegistrationRequestDto.class);
  }

  private void confirmRegistrationRequest(String confirmationKey) throws Exception {
    mvc
      .perform(post("/registration/verify").content("token=" + confirmationKey)
        .contentType(APPLICATION_FORM_URLENCODED))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("verificationSuccess"));
  }

  @Test
  public void testRegistrationFieldReadOnlyGetterAndSetter() {
    RegistrationFieldProperties properties = new RegistrationFieldProperties();

    assertFalse(properties.isReadOnly());

    properties.setReadOnly(true);
    assertTrue(properties.isReadOnly());
  }

  @Test
  public void testRegistrationFieldExternalAuthAttributeGetterAndSetter() {
    RegistrationFieldProperties properties = new RegistrationFieldProperties();

    assertNull(properties.getExternalAuthAttribute());

    String testValue = "TestAttribute";
    properties.setExternalAuthAttribute(testValue);
    assertEquals(testValue, properties.getExternalAuthAttribute());
  }

}
