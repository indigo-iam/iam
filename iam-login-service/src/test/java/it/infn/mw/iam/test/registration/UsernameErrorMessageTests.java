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

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;

@SpringBootTest(classes = {IamLoginService.class})
@AutoConfigureMockMvc
@Transactional
class UsernameErrorMessageTests implements StructuredScopeTestSupportConstants {

  @Autowired
  ObjectMapper mapper;

  @Autowired
  MockMvc mvc;

  private RegistrationRequestDto createRegistrationRequest(String username) {

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(username + "@example.org");
    request.setUsername(username);
    request.setNotes("Some short notes...");
    return request;
  }

  @Test
  void errorMessageTest() throws Exception {

    final String INVALID_USERNAME = "test/";

    RegistrationRequestDto r = createRegistrationRequest(INVALID_USERNAME);

    mvc
      .perform(post("/registration/create").with(csrf().asHeader())
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(r)))
      .andExpect(jsonPath("error").value(
          "Invalid registration request: invalid username (the provided username is not a valid UNIX username)"));
  }

}
