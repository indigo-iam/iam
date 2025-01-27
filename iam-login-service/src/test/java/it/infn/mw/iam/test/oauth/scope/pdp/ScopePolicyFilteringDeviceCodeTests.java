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
package it.infn.mw.iam.test.oauth.scope.pdp;

import static com.google.common.collect.Sets.newHashSet;
import static it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy.PATH;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.SystemScopeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ActiveProfiles({"h2-test", "h2", "wlcg-scopes"})
@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class ScopePolicyFilteringDeviceCodeTests extends ScopePolicyTestUtils {

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamScopePolicyRepository scopePolicyRepo;

  @Autowired
  private SystemScopeService scopeService;

  @Autowired
  private MockMvc mvc;

  @Autowired
  protected ObjectMapper mapper;

  IamAccount findTestAccount() {
    return accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found!"));
  }

  private void setupPolicyAndScopes() {
    IamScopePolicy up = initDenyScopePolicy();
    up.setRule(PolicyRule.DENY);
    up.setScopes(newHashSet("storage.read:/", "storage.write:/"));
    up.setMatchingPolicy(PATH);

    scopePolicyRepo.save(up);

    scopeService.save(new SystemScope("storage.read:/"));
    scopeService.save(new SystemScope("storage.write:/"));
  }

  @Test
  public void deviceCodeFlowScopeFilteringByAccountWorks() throws Exception {

    IamAccount testAccount = findTestAccount();

    IamScopePolicy up = initDenyScopePolicy();
    up.setAccount(testAccount);
    up.setRule(PolicyRule.DENY);
    up.setScopes(Sets.newHashSet("profile"));

    scopePolicyRepo.save(up);

    String response = mvc
      .perform(post("/devicecode").contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic("device-code-client", "secret"))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile email"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get("/device"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/login").param("username", "test")
        .param("password", "password")
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/device"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(post("/device/verify").param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andExpect(model().attribute("scope", "openid email"));

  }

  @Test
  public void deviceCodeMatchingPolicyFilteringWorks() throws Exception {
    setupPolicyAndScopes();

    String response = mvc
      .perform(post("/devicecode").contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic("device-code-client", "secret"))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile storage.read:/ storage.read:/that/thing storage.write:/"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get("/device"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/login").param("username", "test")
        .param("password", "password")
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/device"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(post("/device/verify").param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andExpect(model().attribute("scope", "openid profile"));
  }

  @Test
  public void deviceCodeFlowAdminScopeFilteringWorks() throws Exception {

    String response = mvc
      .perform(post("/devicecode").contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic("device-code-client", "secret"))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile email iam:admin.read"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get("/device"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/login").param("username", "test")
        .param("password", "password")
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/device"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(post("/device/verify").param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andExpect(model().attribute("scope", not(containsString("iam:admin.read"))))
      .andExpect(model().attribute("scope", containsString("openid")))
      .andExpect(model().attribute("scope", containsString("profile")))
      .andExpect(model().attribute("scope", containsString("email")));

  }
}
