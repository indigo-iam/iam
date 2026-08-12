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
package it.infn.mw.iam.test.api.consent;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.type.TypeReference;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.account.approved_site.dto.ConsentGrantWithClientDetailsDTO;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.util.TokenGetterUtils;
import it.infn.mw.iam.test.util.clock.MutableClock;

@SpringBootTest(classes = {IamLoginService.class, ClockConfig.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
public class ConsentGrantControllerTests extends TokenGetterUtils {
  public static final String AUTHORIZE_URL = "http://localhost/authorize";

  public static final String SCOPE = "openid profile";

  @Autowired
  MutableClock clock;

  @Test
  @WithMockUser(username = TEST_USERNAME, roles = {"USER"})
  void testIamApiApprovedReturnsClientDetailsAndCanBeRemoved() throws Exception {

    MockHttpSession session = performImplicitFlowAndGetSession("until-revoked");

    ConsentGrantWithClientDetailsDTO dto =
        mapper
          .readValue(
              mvc.perform(get("/iam/api/approved").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0]").exists())
                .andExpect(jsonPath("$[0].id").exists())
                .andExpect(jsonPath("$[0].userId").value(TEST_USERNAME))
                .andExpect(jsonPath("$[0].clientId").value(IMPLICIT_CLIENT_ID))
                .andExpect(jsonPath("$[0].clientName").value("Implicit Flow client"))
                .andExpect(
                    jsonPath("$[0].clientDescription").value("implicit-flow-client description"))
                .andExpect(jsonPath("$[0].authorizationDate").isNotEmpty())
                .andExpect(jsonPath("$[0].accessDate").isNotEmpty())
                .andExpect(jsonPath("$[0].timeoutDate").doesNotExist())
                .andExpect(jsonPath("$[0].allowedScopes", containsInAnyOrder("openid", "profile")))
                .andReturn()
                .getResponse()
                .getContentAsString(),
              new TypeReference<List<ConsentGrantWithClientDetailsDTO>>() {})
          .get(0);

    mvc.perform(get("/iam/api/approved/" + dto.id()).session(session))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id").value(dto.id()))
      .andExpect(jsonPath("$.userId").value(TEST_USERNAME))
      .andExpect(jsonPath("$.clientId").value(IMPLICIT_CLIENT_ID))
      .andExpect(jsonPath("$.clientName").value("Implicit Flow client"))
      .andExpect(jsonPath("$.clientDescription").value("implicit-flow-client description"))
      .andExpect(
          jsonPath("$.authorizationDate").value(dto.authorizationDate().toInstant().toString()))
      .andExpect(jsonPath("$.accessDate").value(dto.accessDate().toInstant().toString()))
      .andExpect(jsonPath("$.timeoutDate").doesNotExist())
      .andExpect(jsonPath("$.allowedScopes", containsInAnyOrder("openid", "profile")));

    mvc.perform(get("/iam/api/approved/" + dto.id()).with(user("admin").roles("USER")))
      .andExpect(status().isForbidden());

    mvc.perform(get("/iam/api/approved/" + dto.id()).with(user("another-user").roles("USER")))
      .andExpect(status().isInternalServerError());

    performImplicitFlowAndExpectNoForwardToConfirmAccess();

    mvc.perform(delete("/iam/api/approved/" + dto.id()).session(session))
      .andExpect(status().isNoContent());

    performImplicitFlowAndExpectForwardToConfirmAccess();
  }

  @Test
  @WithMockUser(username = TEST_USERNAME, roles = {"USER"})
  void testIamApiApprovedEmptyWhenSetNone() throws Exception {

    MockHttpSession session = performImplicitFlowAndGetSession("none");

    mvc.perform(get("/iam/api/approved").session(session))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$[0]").doesNotExist());
  }

  @Test
  @WithMockUser(username = TEST_USERNAME, roles = {"USER"})
  void testIamApiApprovedExistsButLimitedWhenOneHour() throws Exception {

    MockHttpSession session = performImplicitFlowAndGetSession("one-hour");

    mvc.perform(get("/iam/api/approved").session(session))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$[0]").exists())
      .andExpect(jsonPath("$[0].id").exists())
      .andExpect(jsonPath("$[0].userId").value(TEST_USERNAME))
      .andExpect(jsonPath("$[0].clientId").value(IMPLICIT_CLIENT_ID))
      .andExpect(jsonPath("$[0].clientName").value("Implicit Flow client"))
      .andExpect(jsonPath("$[0].clientDescription").value("implicit-flow-client description"))
      .andExpect(jsonPath("$[0].authorizationDate").isNotEmpty())
      .andExpect(jsonPath("$[0].accessDate").isNotEmpty())
      .andExpect(jsonPath("$[0].timeoutDate").exists())
      .andExpect(jsonPath("$[0].allowedScopes", containsInAnyOrder("openid", "profile")));

    clock.advance(Duration.ofHours(2));

    performImplicitFlowAndExpectForwardToConfirmAccess();

  }

  private MockHttpSession performImplicitFlowAndGetSession(String remember) throws Exception {

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

    mvc
      .perform(post("/authorize").with(csrf())
        .param("user_oauth_approval", "true")
        .param("scope_openid", "openid")
        .param("scope_profile", "profile")
        .param("authorize", "Authorize")
        .param("remember", remember)
        .session(session))
      .andExpect(status().is3xxRedirection());

    return session;
  }

  private void performImplicitFlowAndExpectNoForwardToConfirmAccess() throws Exception {

    String authzEndpointUrl = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
      .queryParam("response_type", "token id_token")
      .queryParam("client_id", IMPLICIT_CLIENT_ID)
      .queryParam("redirect_uri", IMPLICIT_CLIENT_REDIRECT_URL)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .build()
      .toUriString();

    mvc.perform(get(authzEndpointUrl)).andExpect(status().is3xxRedirection());
  }

  private void performImplicitFlowAndExpectForwardToConfirmAccess() throws Exception {

    String authzEndpointUrl = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
      .queryParam("response_type", "token id_token")
      .queryParam("client_id", IMPLICIT_CLIENT_ID)
      .queryParam("redirect_uri", IMPLICIT_CLIENT_REDIRECT_URL)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .build()
      .toUriString();

    mvc.perform(get(authzEndpointUrl))
      .andExpect(status().isOk())
      .andExpect(view().name("forward:/oauth/confirm_access"));
  }
}
