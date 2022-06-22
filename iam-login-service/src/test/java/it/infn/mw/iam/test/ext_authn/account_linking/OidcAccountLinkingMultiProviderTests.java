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

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_SESSION_KEY;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION;
import static it.infn.mw.iam.test.ext_authn.oidc.OidcMultiProviderTestConfig.TEST_OIDC_01_ISSUER;
import static it.infn.mw.iam.test.ext_authn.oidc.OidcMultiProviderTestConfig.TEST_OIDC_02_ISSUER;
import static it.infn.mw.iam.test.ext_authn.oidc.OidcTestConfig.TEST_OIDC_CLIENT_ID;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Optional;

import org.junit.After;
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
import it.infn.mw.iam.test.ext_authn.oidc.OidcMultiProviderTestConfig;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oidc.MockOIDCProvider;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, OidcMultiProviderTestConfig.class,
    FullyMockedOidcClientConfiguration.class}, webEnvironment = WebEnvironment.MOCK)
public class OidcAccountLinkingMultiProviderTests {

  @Autowired
  private MockOIDCProvider oidcProvider;

  @Autowired
  private IamAccountRepository iamAccountRepo;

  @Autowired
  private MockMvc mvc;

  private static final String TEST_100_USER = "test_100";
  private static final String OIDC_ACCOUNT_LINKING_ENDPOINT = "/iam/account-linking/OIDC";

  @After
  public void teardown() {
    IamAccount userAccount = iamAccountRepo.findByUsername(TEST_100_USER)
      .orElseThrow(() -> new UsernameNotFoundException("User not found!"));

    userAccount.getOidcIds().stream().forEach(i -> i.setAccount(null));
    userAccount.getOidcIds().clear();
    iamAccountRepo.save(userAccount);
  }

  @Test
  @WithMockUser(username = TEST_100_USER)
  public void testAccountLinkingWithoutIssuerFails() throws Exception {
    MockHttpSession session =
        (MockHttpSession) mvc.perform(post(OIDC_ACCOUNT_LINKING_ENDPOINT).with(csrf().asHeader()))
          .andExpect(status().isFound())
          .andExpect(redirectedUrl("/openid_connect_login"))
          .andReturn()
          .getRequest()
          .getSession();

    mvc.perform(get("/openid_connect_login").session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"));
  }

  @Test
  @WithMockUser(username = TEST_100_USER)
  public void testAccountLinkingWithIssuer() throws Exception {

    MockHttpSession session = (MockHttpSession) mvc
      .perform(post(OIDC_ACCOUNT_LINKING_ENDPOINT).param("id", TEST_OIDC_01_ISSUER)
        .with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/openid_connect_login?iss=" + TEST_OIDC_01_ISSUER))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          equalTo("/iam/account-linking/OIDC")))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(get("/openid_connect_login").param("iss", TEST_OIDC_01_ISSUER).session(session))
      .andExpect(status().isFound())
      .andExpect(MockMvcResultMatchers
        .redirectedUrlPattern(OidcMultiProviderTestConfig.TEST_OIDC_01_AUTHZ_ENDPOINT_URI + "**"))
      .andReturn()
      .getRequest()
      .getSession();

    String state = (String) session.getAttribute("state");
    String nonce = (String) session.getAttribute("nonce");

    oidcProvider.prepareTokenResponse(TEST_OIDC_01_ISSUER, TEST_OIDC_CLIENT_ID, TEST_100_USER,
        nonce);

    session = (MockHttpSession) mvc
      .perform(get("/openid_connect_login").param("iss", TEST_OIDC_01_ISSUER)
        .param("state", state)
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

    IamAccount userAccount = iamAccountRepo.findByOidcId(TEST_OIDC_01_ISSUER, TEST_100_USER)
      .orElseThrow(() -> new UsernameNotFoundException("User not found!"));

    assertThat(userAccount.getUsername(), equalTo(TEST_100_USER));
  }

  @Test
  @WithMockUser(username = TEST_100_USER)
  public void testAccountLinkingBothIssuer() throws Exception {

    MockHttpSession session = (MockHttpSession) mvc
      .perform(post(OIDC_ACCOUNT_LINKING_ENDPOINT).param("id", TEST_OIDC_01_ISSUER)
        .with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/openid_connect_login?iss=" + TEST_OIDC_01_ISSUER))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(get("/openid_connect_login").param("iss", TEST_OIDC_01_ISSUER).session(session))
      .andExpect(status().isFound())
      .andExpect(MockMvcResultMatchers
        .redirectedUrlPattern(OidcMultiProviderTestConfig.TEST_OIDC_01_AUTHZ_ENDPOINT_URI + "**"))
      .andReturn()
      .getRequest()
      .getSession();

    String state = (String) session.getAttribute("state");
    String nonce = (String) session.getAttribute("nonce");

    oidcProvider.prepareTokenResponse(TEST_OIDC_01_ISSUER, TEST_OIDC_CLIENT_ID, TEST_100_USER,
        nonce);

    session = (MockHttpSession) mvc
      .perform(get("/openid_connect_login").param("iss", TEST_OIDC_01_ISSUER)
        .param("state", state)
        .param("code", "1234")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(forwardedUrl("/iam/account-linking/OIDC/done"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(get("/iam/account-linking/OIDC/done").session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"));

    session = (MockHttpSession) mvc
      .perform(post(OIDC_ACCOUNT_LINKING_ENDPOINT).param("id", TEST_OIDC_02_ISSUER)
        .with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/openid_connect_login?iss=" + TEST_OIDC_02_ISSUER))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(get("/openid_connect_login").param("iss", TEST_OIDC_02_ISSUER).session(session))
      .andExpect(status().isFound())
      .andExpect(MockMvcResultMatchers
        .redirectedUrlPattern(OidcMultiProviderTestConfig.TEST_OIDC_02_AUTHZ_ENDPOINT_URI + "**"))
      .andReturn()
      .getRequest()
      .getSession();

    state = (String) session.getAttribute("state");
    nonce = (String) session.getAttribute("nonce");

    oidcProvider.prepareTokenResponse(TEST_OIDC_02_ISSUER, TEST_OIDC_CLIENT_ID, TEST_100_USER,
        nonce);

    session = (MockHttpSession) mvc
      .perform(get("/openid_connect_login").param("iss", TEST_OIDC_02_ISSUER)
        .param("state", state)
        .param("code", "1234")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(forwardedUrl("/iam/account-linking/OIDC/done"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(get("/iam/account-linking/OIDC/done").session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"));

    IamAccount userAccount = iamAccountRepo.findByUsername(TEST_100_USER)
      .orElseThrow(() -> new UsernameNotFoundException("User not found!"));

    assertThat(userAccount.getUsername(), equalTo(TEST_100_USER));
    assertThat(userAccount.getOidcIds(), hasSize(2));

    Optional<IamAccount> account = iamAccountRepo.findByOidcId(TEST_OIDC_01_ISSUER, TEST_100_USER);
    assertThat(account.isPresent(), is(true));

    account = iamAccountRepo.findByOidcId(TEST_OIDC_02_ISSUER, TEST_100_USER);
    assertThat(account.isPresent(), is(true));
  }
}
