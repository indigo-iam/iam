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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AttributeAndLabelEarlyAuthorizationTests {

  private static final String ACCOUNT_ID = "73f16d93-2441-4a50-88ff-85360d78c6b5";
  private static final String GROUP_ID = "f3b5d44e-20df-4c39-9a92-13230ecfd320";
  private static final String MALFORMED_JSON = "{ invalid json";

  @Autowired
  MockMvc mvc;

  static Stream<String> protectedPutPaths() {
    return Stream.of("/iam/account/" + ACCOUNT_ID + "/attributes",
        "/iam/account/" + ACCOUNT_ID + "/labels", "/iam/group/" + GROUP_ID + "/labels");
  }

  @ParameterizedTest
  @MethodSource("protectedPutPaths")
  void ordinaryUserIsRejectedBeforeDeserialization(String path) throws Exception {
    mvc
      .perform(put(path).with(user("ordinary-user").roles("USER"))
        .with(csrf().asHeader())
        .contentType(MediaType.APPLICATION_JSON)
        .content(MALFORMED_JSON))
      .andExpect(status().isForbidden());
  }

  @ParameterizedTest
  @MethodSource("protectedPutPaths")
  void dashboardAdminReachesDeserialization(String path) throws Exception {
    mvc
      .perform(put(path).with(user("admin").roles("USER", "ADMIN"))
        .with(csrf().asHeader())
        .contentType(MediaType.APPLICATION_JSON)
        .content(MALFORMED_JSON))
      .andExpect(status().isBadRequest());
  }
}
