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
package it.infn.mw.iam.test.api.account.password;

import static it.infn.mw.iam.test.util.AuthenticationUtils.adminAuthentication;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.account.password_reset.ResetPasswordDTO;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class PasswordEncodingTests {

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Autowired
  private PersistentUUIDTokenGenerator tokenGenerator;

  @Autowired
  private IamAccountRepository iamAccountRepository;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void cleanupOAuthUser() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void testNoValidResetToken() throws Exception {
    String username = "password_encoded";

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Password encoded");
    request.setFamilyname("Test");
    request.setEmail("password_encoded@example.org");
    request.setUsername(username);
    request.setNotes("Some short notes...");

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String confirmationKey = "NoValidToken";
    mvc
      .perform(post("/registration/verify").content("token=" + confirmationKey)
        .contentType(APPLICATION_FORM_URLENCODED))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("verificationFailure"));

  }

  @Test
  public void testPasswordEncoded() throws Exception {
    String username = "password_encoded";
    String newPassword = "Secure_P@ssw0rd!";

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Password encoded");
    request.setFamilyname("Test");
    request.setEmail("password_encoded@example.org");
    request.setUsername(username);
    request.setNotes("Some short notes...");

    String rs = mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    request = mapper.readValue(rs, RegistrationRequestDto.class);

    String confirmationKey = tokenGenerator.getLastToken();
    mvc.perform(post("/registration/verify").content("token=" + confirmationKey)
        .contentType(APPLICATION_FORM_URLENCODED))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("verificationSuccess"));

    mvc.perform(post("/registration/approve/{uuid}", request.getUuid())
      .with(authentication(adminAuthentication()))
      .contentType(APPLICATION_JSON)).andExpect(status().isOk());

    String resetKey = tokenGenerator.getLastToken();

    ResetPasswordDTO dto = new ResetPasswordDTO();
    dto.setUpdatedPassword(newPassword);
    dto.setToken(resetKey);

    mvc
      .perform(post("/iam/password-reset").content(mapper.writeValueAsString(dto))
        .with(authentication(adminAuthentication()))
        .contentType(MediaType.APPLICATION_JSON))
      .andExpect(MockMvcResultMatchers.status().isCreated());

    IamAccount account = iamAccountRepository.findByUuid(request.getAccountId())
      .orElseThrow(() -> new AssertionError("Expected account not found"));

    Assert.assertTrue(passwordEncoder.matches(newPassword, account.getPassword()));
  }

}
