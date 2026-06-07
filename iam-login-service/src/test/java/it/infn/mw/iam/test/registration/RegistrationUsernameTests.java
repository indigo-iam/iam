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
import static org.junit.jupiter.api.Assertions.assertTrue;
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
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class RegistrationUsernameTests implements StructuredScopeTestSupportConstants {

  @Autowired
  ObjectMapper objectMapper;

  @Autowired
  MockMvc mvc;

  @Autowired
  IamAccountRepository iamAccountRepo;

  @Autowired
  SecurityContextUtils context;

  @BeforeEach
  void setup() {
    context.cleanupSecurityContext();
  }

  private RegistrationRequestDto createRegistrationRequest(String username) {

    String email = username.split("@")[0] + "@example.org";
    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setNotes("Some short notes...");

    return request;
  }

  @Test
  void validUsernames() throws Exception {
    final String[] validUsernames = {"bob", "test$", "root", "test1234", "test_", "_test",
        "username1@example.com", "username2@domain"};

    for (String u : validUsernames) {
      RegistrationRequestDto r = createRegistrationRequest(u);
      mvc
        .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
          .content(objectMapper.writeValueAsString(r)))
        .andExpect(status().isOk());
    }

    IamAccount account = iamAccountRepo.findByUsername("bob")
      .orElseThrow(() -> new AssertionError("Expected account not found"));
    assertTrue(account.getAttributeByName(NICKNAME_ATTRIBUTE_KEY).isEmpty());

    iamAccountRepo.delete(account);

  }

  @Test
  void invalidUsernames() throws Exception {
    final String[] invalidUsernames = {"a", "£$%^&*(", ".,", "-test", "1test", "test$$", "@domain",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};

    for (String u : invalidUsernames) {
      RegistrationRequestDto r = createRegistrationRequest(u);
      mvc
        .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
          .content(objectMapper.writeValueAsString(r)))
        .andExpect(status().isBadRequest());
    }
  }

}
