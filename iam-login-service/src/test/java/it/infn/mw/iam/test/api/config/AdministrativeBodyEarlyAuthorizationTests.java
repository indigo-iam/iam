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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest
@AutoConfigureMockMvc
class AdministrativeBodyEarlyAuthorizationTests {

  private static final String MALFORMED_JSON = "{ invalid json";

  @Autowired
  MockMvc mvc;

  static Stream<Arguments> protectedEndpoints() {
    return Stream.of(
        Arguments.of(HttpMethod.PUT, "/iam/account/73f16d93-2441-4a50-88ff-85360d78c6b5/endTime"),
        Arguments.of(HttpMethod.POST, "/iam/api/clients"),
        Arguments.of(HttpMethod.PUT, "/iam/api/clients/example-client"),
        Arguments.of(HttpMethod.POST, "/iam/scope_policies"),
        Arguments.of(HttpMethod.PUT, "/iam/scope_policies/1"));
  }

  private MockHttpServletRequestBuilder request(HttpMethod method, String path) {
    MockHttpServletRequestBuilder builder = HttpMethod.POST.equals(method) ? post(path) : put(path);
    return builder.with(csrf().asHeader())
      .contentType(MediaType.APPLICATION_JSON)
      .content(MALFORMED_JSON);
  }

  @ParameterizedTest
  @MethodSource("protectedEndpoints")
  void ordinaryUserIsRejectedBeforeDeserialization(HttpMethod method, String path)
      throws Exception {
    mvc.perform(request(method, path).with(user("ordinary-user").roles("USER")))
      .andExpect(status().isForbidden());
  }

  @ParameterizedTest
  @MethodSource("protectedEndpoints")
  void dashboardAdminReachesDeserialization(HttpMethod method, String path) throws Exception {
    mvc.perform(request(method, path).with(user("admin").roles("USER", "ADMIN")))
      .andExpect(status().isBadRequest());
  }
}
