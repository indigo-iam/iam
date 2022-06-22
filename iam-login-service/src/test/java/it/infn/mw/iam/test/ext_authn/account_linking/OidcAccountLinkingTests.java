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
package it.infn.mw.iam.test.ext_authn.account_linking;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_DASHBOARD_ERROR_KEY;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_SESSION_KEY;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTH_ERROR_KEY;
import static it.infn.mw.iam.test.ext_authn.oidc.OidcTestConfig.TEST_OIDC_CLIENT_ID;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.ext_authn.oidc.FullyMockedOidcClientConfiguration;
import it.infn.mw.iam.test.ext_authn.oidc.OidcTestConfig;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oidc.MockOIDCProvider;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, OidcTestConfig.class,
    FullyMockedOidcClientConfiguration.class}, webEnvironment = WebEnvironment.MOCK)
public class OidcAccountLinkingTests {

  @Autowired
  private MockOIDCProvider oidcProvider;

  @Autowired
  private IamAccountRepository iamAccountRepo;

  @Autowired
  private MockMvc mvc;

  private static final String TEST_100_USER = "test_100";

  @Test
  public void accessToAccountLinkingApiFailsForAnonymousUsers() throws Exception {

    mvc.perform(get("/iam/account-linking/OIDC")).andExpect(status().isUnauthorized());
    mvc.perform(get("/iam/account-linking/SAML")).andExpect(status().isUnauthorized());
    
  }

  @Test
  @WithMockUser(username = TEST_100_USER)
  public void accountLinkingFinalizationFailsForUserWithoutExternalAuthToken() throws Exception {

  }

  @Test
  @WithMockUser(username = TEST_100_USER)
  public void oidcAccountLinkingWorks() throws Exception {

    MockHttpSession session = (MockHttpSession) mvc
      .perform(post("/iam/account-linking/OIDC").with(csrf().asHeader()))
      .andDo(print())
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/openid_connect_login"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          equalTo("/iam/account-linking/OIDC")))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("/openid_connect_login").session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrlPattern(OidcTestConfig.TEST_OIDC_AUTHORIZATION_ENDPOINT_URI + "**"))
      .andReturn()
      .getRequest()
      .getSession();

    String state = (String) session.getAttribute("state");
    String nonce = (String) session.getAttribute("nonce");

    oidcProvider.prepareTokenResponse(TEST_OIDC_CLIENT_ID, TEST_100_USER, nonce);

    session =
        (MockHttpSession) mvc
          .perform(get("/openid_connect_login").param("state", state)
            .param("code", "1234")
            .session(session))
          .andExpect(status().isOk())
          .andExpect(forwardedUrl("/iam/account-linking/OIDC/done"))
          .andReturn()
          .getRequest()
          .getSession();

    session = (MockHttpSession) mvc.perform(get("/iam/account-linking/OIDC/done").session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, nullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY, nullValue()))
      .andReturn()
      .getRequest()
      .getSession();

    IamAccount userAccount =
        iamAccountRepo.findByOidcId(OidcTestConfig.TEST_OIDC_ISSUER, TEST_100_USER)
          .orElseThrow(() -> new UsernameNotFoundException("User not found!"));

    assertThat(userAccount.getUsername(), Matchers.equalTo(TEST_100_USER));

    userAccount.getOidcIds().stream().forEach(i -> i.setAccount(null));
    userAccount.getOidcIds().clear();
    iamAccountRepo.save(userAccount);

  }

  @Test
  @WithMockUser(username = TEST_100_USER)
  public void oidcAccountLinkingFailsSinceOidcIdIsAlreadyBoundToAnotherUser() throws Exception {

    MockHttpSession session = (MockHttpSession) mvc
      .perform(post("/iam/account-linking/OIDC").with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/openid_connect_login"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          Matchers.equalTo("/iam/account-linking/OIDC")))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("/openid_connect_login").session(session))
      .andExpect(status().isFound())
      .andExpect(MockMvcResultMatchers
        .redirectedUrlPattern(OidcTestConfig.TEST_OIDC_AUTHORIZATION_ENDPOINT_URI + "**"))
      .andReturn()
      .getRequest()
      .getSession();

    String state = (String) session.getAttribute("state");
    String nonce = (String) session.getAttribute("nonce");

    oidcProvider.prepareTokenResponse(TEST_OIDC_CLIENT_ID, "test-user", nonce);

    session =
        (MockHttpSession) mvc
          .perform(get("/openid_connect_login").param("state", state)
            .param("code", "1234")
            .session(session))
          .andExpect(status().isOk())
          .andExpect(forwardedUrl("/iam/account-linking/OIDC/done"))
          .andReturn()
          .getRequest()
          .getSession();


    String expectedErrorMessage =
        String.format("OpenID connect account '[%s] %s' is already linked to another user",
            OidcTestConfig.TEST_OIDC_ISSUER, "test-user");

    mvc.perform(get("/iam/account-linking/OIDC/done").session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, nullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY, nullValue()))
      .andExpect(
          flash().attribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY, equalTo(expectedErrorMessage)));

  }

  @Test
  @WithMockUser(username = "test")
  public void oidcAccountLinkingFailsSinceOidcIdIsAlreadyBoundToAuthenticatedUser()
      throws Exception {

    MockHttpSession session = (MockHttpSession) mvc
      .perform(post("/iam/account-linking/OIDC").with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/openid_connect_login"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          Matchers.equalTo("/iam/account-linking/OIDC")))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("/openid_connect_login").session(session))
      .andExpect(status().isFound())
      .andExpect(MockMvcResultMatchers
        .redirectedUrlPattern(OidcTestConfig.TEST_OIDC_AUTHORIZATION_ENDPOINT_URI + "**"))
      .andReturn()
      .getRequest()
      .getSession();

    String state = (String) session.getAttribute("state");
    String nonce = (String) session.getAttribute("nonce");

    oidcProvider.prepareTokenResponse(TEST_OIDC_CLIENT_ID, "test-user", nonce);
    session =
        (MockHttpSession) mvc
          .perform(get("/openid_connect_login").param("state", state)
            .param("code", "1234")
            .session(session))
          .andExpect(status().isOk())
          .andExpect(forwardedUrl("/iam/account-linking/OIDC/done"))
          .andReturn()
          .getRequest()
          .getSession();


    String expectedErrorMessage =
        String.format("OpenID connect account '[%s] %s' is already linked to user '%s'",
            OidcTestConfig.TEST_OIDC_ISSUER, "test-user", "test");

    mvc.perform(get("/iam/account-linking/OIDC/done").session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, nullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY, nullValue()))
      .andExpect(
          flash().attribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY, equalTo(expectedErrorMessage)));

  }

  @Test
  @WithMockUser(username = TEST_100_USER)
  public void oidcAccountLinkingExternalAuthnFailureRedirectsToDashboard() throws Exception {
    MockHttpSession session = (MockHttpSession) mvc
      .perform(post("/iam/account-linking/OIDC").with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/openid_connect_login"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          Matchers.equalTo("/iam/account-linking/OIDC")))
      .andReturn()
      .getRequest()
      .getSession();


    session = (MockHttpSession) mvc.perform(get("/openid_connect_login").session(session))
      .andExpect(status().isFound())
      .andExpect(MockMvcResultMatchers
        .redirectedUrlPattern(OidcTestConfig.TEST_OIDC_AUTHORIZATION_ENDPOINT_URI + "**"))
      .andReturn()
      .getRequest()
      .getSession();

    String state = (String) session.getAttribute("state");

    oidcProvider.prepareError("invalid_request", "this is an error");

    mvc
      .perform(
          get("/openid_connect_login").param("state", state).param("code", "1234").session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, nullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY, nullValue()))
      .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, notNullValue()))
      .andExpect(authenticated().withUsername(TEST_100_USER));

  }

}
