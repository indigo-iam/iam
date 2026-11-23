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
package it.infn.mw.iam.test.logout;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class LogoutTests {

  @Autowired
  private MockMvc mockMvc;

  @Test
  void logoutWithValidCsrfTokenShouldSucceed() throws Exception {
    mockMvc.perform(post("/logout").with(user("testuser")).with(csrf()))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("/login?logout"));
  }

  @Test
  void logoutWithInvalidCsrfTokenShouldBeRejected() throws Exception {
    mockMvc.perform(post("/logout").with(user("testuser")).with(csrf().useInvalidToken()))
      .andExpect(status().isForbidden());
  }

  @Test
  void logoutWithoutCsrfTokenShouldBeRejected() throws Exception {
    mockMvc.perform(post("/logout").with(user("testuser"))).andExpect(status().isForbidden());
  }
}
