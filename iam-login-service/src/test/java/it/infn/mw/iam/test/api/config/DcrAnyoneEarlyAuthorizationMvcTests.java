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
package it.infn.mw.iam.test.api.config;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.config.ClockConfig;

/**
 * Verifies that the ANYONE policy still lets anonymous DCR requests reach JSON parsing.
 */
@SpringBootTest(classes = {IamLoginService.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK,
    properties = "client-registration.allow-for=ANYONE")
@AutoConfigureMockMvc
class DcrAnyoneEarlyAuthorizationMvcTests {

  private static final String MALFORMED_JSON = "{ invalid json";

  @Autowired
  MockMvc mvc;

  @ParameterizedTest
  @ValueSource(strings = {"/resource"})
  void anonymousRequestReachesDeserialization(String path) throws Exception {
    mvc.perform(post(path)
        .with(csrf().asHeader())
        .contentType(MediaType.APPLICATION_JSON)
        .content(MALFORMED_JSON))
      .andExpect(status().isBadRequest());
  }

  @ParameterizedTest
  @ValueSource(strings = {"/iam/api/client-registration"})
  void authenticatedUserReachesDeserialization(String path) throws Exception {
    mvc.perform(post(path)
        .with(csrf().asHeader())
        .with(user("member").roles("USER"))
        .contentType(MediaType.APPLICATION_JSON)
        .content(MALFORMED_JSON))
      .andExpect(status().isBadRequest());
  }
}
