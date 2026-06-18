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
package it.infn.mw.iam.test.api.account.approvedSite;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import it.infn.mw.iam.test.util.TokenGetterUtils;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc(printOnlyOnFailure = true)
@Transactional
public class ApprovedSiteControllerTests extends TokenGetterUtils {
  public static final String AUTHORIZE_URL = "http://localhost/authorize";

  public static final String SCOPE = "openid profile";

  @Autowired
  MockMvc mvc;

  @Test
  @WithMockUser(username = TEST_USERNAME, roles = { "USER" })
  void testIamApiApprovedReturnsClientDetails() throws Exception {

        MockHttpSession session = performImplicitFlowAndGetSession();

        mvc.perform(get("/iam/api/approved").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0]").exists())
                .andExpect(jsonPath("$[0].userId").value(TEST_USERNAME))
                .andExpect(jsonPath("$[0].clientId").value(IMPLICIT_CLIENT_ID))
                .andExpect(jsonPath("$[0].clientName").value("Implicit Flow client"))
                .andExpect(jsonPath("$[0].clientDescription")
                                .value("implicit-flow-client description"))
                .andExpect(jsonPath("$[0].authorizationDate").isNotEmpty())
                .andExpect(jsonPath("$[0].accessDate").isNotEmpty())
                .andExpect(jsonPath("$[0].timeoutDate").doesNotExist())
                .andExpect(jsonPath("$[0].allowedScopes",
                                containsInAnyOrder("openid", "profile")));
  }

  private MockHttpSession performImplicitFlowAndGetSession() throws Exception {

        String authzEndpointUrl = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
                        .queryParam("response_type", "token id_token")
                        .queryParam("client_id", IMPLICIT_CLIENT_ID)
                        .queryParam("redirect_uri", IMPLICIT_CLIENT_REDIRECT_URL)
                        .queryParam("scope", SCOPE)
                        .queryParam("nonce", "1")
                        .queryParam("state", "1")
                        .build()
                        .toUriString();

        MockHttpSession session = (MockHttpSession) mvc.perform(get(authzEndpointUrl))
                        .andExpect(status().isOk())
                        .andExpect(view().name("forward:/oauth/confirm_access"))
                        .andReturn()
                        .getRequest()
                        .getSession();

        mvc.perform(post("/authorize").with(csrf())
                        .param("user_oauth_approval", "true")
                        .param("scope_openid", "openid")
                        .param("scope_profile", "profile")
                        .param("authorize", "Authorize")
                        .param("remember", "until-revoked")
                        .session(session))
                        .andExpect(status().is3xxRedirection());

        return session;
  }
}
