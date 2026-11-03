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

import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_SECRET;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.util.oauth.OAuthTokenTestUtils;

@SpringBootTest(classes = {IamLoginService.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
class GroupAttributeEarlyAuthorizationTests {

  private static final String GROUP_ATTRIBUTES =
      "/iam/group/73f16d93-2441-4a50-88ff-85360d78c6b5/attributes";

  @Autowired
  MockMvc mvc;

  @Autowired
  ObjectMapper objectMapper;

  @Test
  void missingAdminWriteScopeRejectsMalformedBodyBeforeMvc() throws Exception {
    String token = OAuthTokenTestUtils.clientCredentialsToken(mvc, objectMapper,
        SCIM_CLIENT_ID, SCIM_CLIENT_SECRET, SCIM_READ_SCOPE);

    mvc.perform(put(GROUP_ATTRIBUTES)
      .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
      .contentType(MediaType.APPLICATION_JSON)
      .content("{ invalid json"))
      .andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void dashboardAdminAllowsMalformedBodyToReachMvc() throws Exception {
    mvc.perform(put(GROUP_ATTRIBUTES)
      .with(csrf())
      .contentType(MediaType.APPLICATION_JSON)
      .content("{ invalid json"))
      .andExpect(status().isBadRequest());
  }
}
