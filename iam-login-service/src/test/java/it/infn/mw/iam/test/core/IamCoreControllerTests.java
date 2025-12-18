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
package it.infn.mw.iam.test.core;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.WithMockOIDCUser;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
@TestPropertySource(properties = {"spring.main.allow-bean-definition-overriding=true",})
@Transactional
class IamCoreControllerTests {

  @Autowired
  MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  MockMvc mvc;

  @Value("${iam.baseUrl}")
  String iamBaseUrl;

  @BeforeEach
  void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @AfterEach
  void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  void startRegistrationRedirectsToRegisterPage() throws Exception {
    mvc.perform(get("/start-registration"))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/register"));

  }

  @Test
  void unauthenticatedUserIsRedirectedToLoginPage() throws Exception {

    // Here the spring security filter assumes we run on localhost:80
    mvc.perform(get("/"))
      .andDo(print())
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("http://localhost/login"));

    mvc.perform(get("/login"))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"));

  }

  @Test
  void anonymousIsAcceptedAtLoginPage() throws Exception {

    mvc.perform(get("/login"))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"));

  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  void authenticatedUserIsRedirectedToRoot() throws Exception {

    mvc.perform(get("/login"))
      .andDo(print())
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/"));
  }

  @Test
  @WithMockOIDCUser
  void externallyAuthenticatedUserIsRedirectedToRegisterPage() throws Exception {
    mvc.perform(get("/login"))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(forwardedUrl("/start-registration"));
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  void resetSessionClearsSecurityContext() throws Exception {
    mvc.perform(get("/reset-session"))
      .andDo(print())
      .andExpect(status().isFound())
      .andExpect(unauthenticated());
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  void authenticatedAccessToRootLeadsToMitreWebapp() throws Exception {
    mvc.perform(get("/")).andDo(print()).andExpect(status().isOk()).andExpect(view().name("home"));
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  void authenticatedAccessToManageLeadsToMitreManageWebapp() throws Exception {
    mvc.perform(get("/manage"))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(view().name("manage"));
  }

  @Test
  @WithMockOAuthUser(clientId = "client-cred", scopes = {"openid"}, authorities = {"ROLE_CLIENT"})
  void userinfoDeniesAccessForClientCredentialsClient() throws Exception {

    mvc.perform(get("/userinfo")).andDo(print()).andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(scopes = {"openid"}, user = "not-found", authorities = {"ROLE_USER"})
  void userinfoReturns404ForUserNotFound() throws Exception {

    mvc.perform(get("/userinfo")).andDo(print()).andExpect(status().isNotFound());
  }


  @Test
  @WithMockOAuthUser(scopes = {"openid", "profile", "email"}, user = "test",
      authorities = {"ROLE_USER"}, externallyAuthenticated = true,
      externalAuthenticationType = ExternalAuthenticationType.OIDC)
  void userInfoReturnsExternalAuthenticationInfo() throws Exception {

    mvc.perform(get("/userinfo"))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.external_authn.type", equalTo("oidc")));
  }

  @Test
  @WithMockOAuthUser(scopes = {"openid profile"}, user = "test", authorities = {"ROLE_USER"})
  void userinfoWithClaims() throws Exception {

    String userInfoClaimsRequest = "{ \"userinfo\" : { \"groups\": null }}";

    mvc.perform(get("/userinfo").param("claims", userInfoClaimsRequest))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.groups", hasSize(3)));
  }

  @Test
  void testWebfingerUserFound() throws Exception {
    mvc
      .perform(get("/.well-known/webfinger").param("resource", "acct:test@iam.test")
        .param("rel", "http://openid.net/specs/connect/1.0/issuer"))
      .andExpect(status().isOk());

  }

  @Test
  void testWebfingerUserNotFound() throws Exception {
    mvc
      .perform(get("/.well-known/webfinger").param("resource", "acct:not-found@example.org")
        .param("rel", "http://openid.net/specs/connect/1.0/issuer"))
      .andExpect(status().isNotFound());

  }

  @Test
  void testUnknownUriFormat() throws Exception {
    mvc
      .perform(get("/.well-known/webfinger").param("resource", "xyz://not.supported")
        .param("rel", "http://openid.net/specs/connect/1.0/issuer"))
      .andExpect(status().isNotFound());

  }

  @Test
  void testWebfingerNonOidcRel() throws Exception {
    mvc
      .perform(get("/.well-known/webfinger").param("resource", "acct:not-found@example.org")
        .param("rel", "another.rel"))
      .andExpect(status().isNotFound());

  }

  @Test
  void testErrorPage() {
    Assertions
      .assertThatThrownBy(() -> mvc.perform(get("/error").contentType(MediaType.APPLICATION_JSON)))
      .hasCauseInstanceOf(RuntimeException.class)
      .hasMessageContaining(
          "Request processing failed; nested exception is java.lang.NullPointerException");
  }
}
