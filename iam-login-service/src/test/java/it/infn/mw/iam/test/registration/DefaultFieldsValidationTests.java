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

import static it.infn.mw.iam.registration.DefaultRegistrationRequestService.NICKNAME_ATTRIBUTE_KEY;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.DEFAULT_IDP_ID;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
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
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamRegistrationRequestRepository;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.ext_authn.oidc.OidcTestConfig;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;
import it.infn.mw.iam.test.util.WithMockOIDCUser;
import it.infn.mw.iam.test.util.WithMockSAMLUser;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class DefaultFieldsValidationTests implements StructuredScopeTestSupportConstants {

  static final String TEST_ATTRIBUTES_USERNAME = "test-attributes";
  static final String TEST_ATTRIBUTES_EMAIL = TEST_ATTRIBUTES_USERNAME + "@example.org";
  static final String TEST_ATTRIBUTES_GIVENNAME = "Test";
  static final String TEST_ATTRIBUTES_FAMILYNAME = "User";

  static final String SAML_SUBJECT = "a957c196-0cac-4c24-a36f-972f2fa916a9";
  static final String SAML_USERNAME = "saml-username";
  static final String SAML_EMAIL = SAML_USERNAME + "@example.org";
  static final String SAML_GIVENNAME = "SAML";
  static final String SAML_FAMILYNAME = "Remote";

  static final String OIDC_SUBJECT = "a957c196-0cac-4c24-a36f-972f2fa916a9";
  static final String OIDC_USERNAME = "oidc-username";
  static final String OIDC_EMAIL = OIDC_USERNAME + "@example.org";
  static final String OIDC_GIVENNAME = "OIDC";
  static final String OIDC_FAMILYNAME = "Remote";

  @Autowired
  ObjectMapper objectMapper;

  @Autowired
  MockMvc mvc;

  @Autowired
  IamAccountRepository iamAccountRepo;

  @Autowired
  IamRegistrationRequestRepository registrationRequestRepo;

  @Autowired
  SecurityContextUtils context;

  @BeforeEach
  void setup() {
    context.cleanupSecurityContext();
  }

  private RegistrationRequestDto createTestRegistrationRequest() {

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname(TEST_ATTRIBUTES_GIVENNAME);
    request.setFamilyname(TEST_ATTRIBUTES_FAMILYNAME);
    request.setEmail(TEST_ATTRIBUTES_EMAIL);
    request.setUsername(TEST_ATTRIBUTES_USERNAME);
    request.setNotes("Some short notes...");
    return request;
  }

  private RegistrationRequestDto createSamlRegistrationRequest() {

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname(SAML_GIVENNAME);
    request.setFamilyname(SAML_FAMILYNAME);
    request.setEmail(SAML_EMAIL);
    request.setUsername(SAML_USERNAME);
    request.setNotes("Some short notes...");
    return request;
  }

  private RegistrationRequestDto createOidcRegistrationRequest() {

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname(OIDC_GIVENNAME);
    request.setFamilyname(OIDC_FAMILYNAME);
    request.setEmail(OIDC_EMAIL);
    request.setUsername(OIDC_USERNAME);
    request.setNotes("Some short notes...");
    return request;
  }

  @Test
  void anonymousRequestWithReadOnlyFieldsFails() throws Exception {

    RegistrationRequestDto request = createTestRegistrationRequest();
    mvc
      .perform(post("/registration/create").contentType(APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(request)))
      .andExpect(status().isOk());

    IamAccount account = iamAccountRepo.findByEmail(TEST_ATTRIBUTES_EMAIL)
      .orElseThrow(() -> new AssertionError("Expected account not found"));

    assertThat(account.getUsername(), is(TEST_ATTRIBUTES_USERNAME));
    assertThat(account.getUserInfo().getGivenName(), is(TEST_ATTRIBUTES_GIVENNAME));
    assertThat(account.getUserInfo().getFamilyName(), is(TEST_ATTRIBUTES_FAMILYNAME));
    assertThat(account.getUserInfo().getEmail(), is(TEST_ATTRIBUTES_EMAIL));
    assertThat(account.getConfirmationKey(), notNullValue());
    assertThat(account.isActive(), is(false));
    assertThat(account.getAttributeByName(NICKNAME_ATTRIBUTE_KEY).isEmpty(), is(true));

    IamRegistrationRequest registrationRequest =
        registrationRequestRepo.findByAccountConfirmationKey(account.getConfirmationKey())
          .orElseThrow(() -> new AssertionError("Expected registration request not found"));

    assertThat(registrationRequest.getStatus(), is(IamRegistrationRequestStatus.NEW));
    assertThat(registrationRequest.getAccount().getId(), is(account.getId()));

    iamAccountRepo.delete(account);
  }

  @Test
  @WithMockSAMLUser(issuer = DEFAULT_IDP_ID, username = SAML_USERNAME, givenName = SAML_GIVENNAME,
      familyName = SAML_FAMILYNAME, email = SAML_EMAIL, subject = SAML_SUBJECT)
  void samlAuthenticatedRequestWorksAndNicknameIsNotSet() throws Exception {

    RegistrationRequestDto r = createSamlRegistrationRequest();
    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(r)))
      .andExpect(status().isOk());

    IamAccount account = iamAccountRepo.findByEmail(SAML_EMAIL)
      .orElseThrow(() -> new AssertionError("Expected account not found"));

    assertThat(account.getUsername(), is(SAML_USERNAME));
    assertThat(account.getUserInfo().getGivenName(), is(SAML_GIVENNAME));
    assertThat(account.getUserInfo().getFamilyName(), is(SAML_FAMILYNAME));
    assertThat(account.getUserInfo().getEmail(), is(SAML_EMAIL));
    assertThat(account.getConfirmationKey(), notNullValue());
    assertThat(account.isActive(), is(false));
    assertThat(account.getAttributeByName(NICKNAME_ATTRIBUTE_KEY).isEmpty(), is(true));

    IamRegistrationRequest registrationRequest =
        registrationRequestRepo.findByAccountConfirmationKey(account.getConfirmationKey())
          .orElseThrow(() -> new AssertionError("Expected registration request not found"));

    assertThat(registrationRequest.getStatus(), is(IamRegistrationRequestStatus.NEW));
    assertThat(registrationRequest.getAccount().getId(), is(account.getId()));

    iamAccountRepo.delete(account);
  }

  @Test
  @WithMockOIDCUser(subject = OIDC_SUBJECT, issuer = OidcTestConfig.TEST_OIDC_ISSUER,
      givenName = OIDC_GIVENNAME, familyName = OIDC_FAMILYNAME, username = OIDC_USERNAME,
      email = OIDC_EMAIL)
  void oidcAuthenticatedRequestWorksAndNicknameIsNotSet() throws Exception {

    RegistrationRequestDto r = createOidcRegistrationRequest();
    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(r)))
      .andExpect(status().isOk());

    IamAccount account = iamAccountRepo.findByEmail(OIDC_EMAIL)
      .orElseThrow(() -> new AssertionError("Expected account not found"));

    assertThat(account.getUsername(), is(OIDC_USERNAME));
    assertThat(account.getUserInfo().getGivenName(), is(OIDC_GIVENNAME));
    assertThat(account.getUserInfo().getFamilyName(), is(OIDC_FAMILYNAME));
    assertThat(account.getUserInfo().getEmail(), is(OIDC_EMAIL));
    assertThat(account.getConfirmationKey(), notNullValue());
    assertThat(account.isActive(), is(false));
    assertThat(account.getAttributeByName(NICKNAME_ATTRIBUTE_KEY).isEmpty(), is(true));

    IamRegistrationRequest registrationRequest =
        registrationRequestRepo.findByAccountConfirmationKey(account.getConfirmationKey())
          .orElseThrow(() -> new AssertionError("Expected registration request not found"));

    assertThat(registrationRequest.getStatus(), is(IamRegistrationRequestStatus.NEW));
    assertThat(registrationRequest.getAccount().getId(), is(account.getId()));

    iamAccountRepo.delete(account);
  }

  @Test
  @WithMockSAMLUser(issuer = DEFAULT_IDP_ID, username = SAML_USERNAME, givenName = SAML_GIVENNAME,
      familyName = SAML_FAMILYNAME, email = SAML_EMAIL, subject = SAML_SUBJECT)
  void samlAuthenticatedRequestValidWhenManipulated() throws Exception {

    RegistrationRequestDto r = createSamlRegistrationRequest();
    r.setUsername("custom-username");

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(r)))
      .andExpect(status().isOk());

    iamAccountRepo.delete(iamAccountRepo.findByEmail(SAML_EMAIL)
      .orElseThrow(() -> new AssertionError("Expected account not found")));

    r = createSamlRegistrationRequest();
    r.setGivenname("custom-name");

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(r)))
      .andExpect(status().isOk());

    iamAccountRepo.delete(iamAccountRepo.findByEmail(SAML_EMAIL)
      .orElseThrow(() -> new AssertionError("Expected account not found")));

    r = createSamlRegistrationRequest();
    r.setFamilyname("custom-surname");

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(r)))
      .andExpect(status().isOk());

    iamAccountRepo.delete(iamAccountRepo.findByEmail(SAML_EMAIL)
      .orElseThrow(() -> new AssertionError("Expected account not found")));

    r = createSamlRegistrationRequest();
    r.setEmail("custom-email@example.com");

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(r)))
      .andExpect(status().isOk());

    iamAccountRepo.delete(iamAccountRepo.findByEmail("custom-email@example.com")
      .orElseThrow(() -> new AssertionError("Expected account not found")));
  }

  @Test
  @WithMockOIDCUser(subject = OIDC_SUBJECT, issuer = OidcTestConfig.TEST_OIDC_ISSUER,
      givenName = OIDC_GIVENNAME, familyName = OIDC_FAMILYNAME, username = OIDC_USERNAME,
      email = OIDC_EMAIL)
  void oidcAuthenticatedRequestInvalidDueToDtoManipulation() throws Exception {

    RegistrationRequestDto r = createOidcRegistrationRequest();
    r.setUsername("custom-username");

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(r)))
      .andExpect(status().isOk());

    iamAccountRepo.delete(iamAccountRepo.findByEmail(OIDC_EMAIL)
      .orElseThrow(() -> new AssertionError("Expected account not found")));

    r = createOidcRegistrationRequest();
    r.setGivenname("custom-name");

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(r)))
      .andExpect(status().isOk());

    iamAccountRepo.delete(iamAccountRepo.findByEmail(OIDC_EMAIL)
      .orElseThrow(() -> new AssertionError("Expected account not found")));

    r = createOidcRegistrationRequest();
    r.setFamilyname("custom-surname");

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(r)))
      .andExpect(status().isOk());

    iamAccountRepo.delete(iamAccountRepo.findByEmail(OIDC_EMAIL)
      .orElseThrow(() -> new AssertionError("Expected account not found")));

    r = createOidcRegistrationRequest();
    r.setEmail("custom-email@example.com");

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(r)))
      .andExpect(status().isOk());

    iamAccountRepo.delete(iamAccountRepo.findByEmail("custom-email@example.com")
      .orElseThrow(() -> new AssertionError("Expected account not found")));
  }

}
