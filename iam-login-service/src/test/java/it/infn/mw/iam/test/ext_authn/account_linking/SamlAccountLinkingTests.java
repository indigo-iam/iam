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
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.EPUID;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.saml.SamlUtils;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class},
    webEnvironment = WebEnvironment.MOCK)
public class SamlAccountLinkingTests extends SamlAuthenticationTestSupport {

  private static final String TEST_100_USER = "test_100";

  @Autowired
  private IamAccountRepository iamAccountRepo;

  @Test
  @WithMockUser(username = TEST_100_USER)
  public void samlAccountLinkingWorks() throws Throwable {

    MockHttpSession session = (MockHttpSession) mvc
      .perform(post("/iam/account-linking/SAML").with(csrf().asHeader()))
      .andDo(MockMvcResultHandlers.print())
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/saml/login"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          Matchers.equalTo("/iam/account-linking/SAML")))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get(samlDefaultIdpLoginUrl()).session(session))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        Matchers.equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildTest1Response(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(status().isOk())
      .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, nullValue()))
      .andExpect(forwardedUrl("/iam/account-linking/SAML/done"))
      .andExpect(authenticated().withUsername(TEST_100_USER))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(get("/iam/account-linking/SAML/done").session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, nullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY, nullValue()));

    IamSamlId samlId  = new IamSamlId(DEFAULT_IDP_ID, EPUID.getAttributeName(),
        T1_EPUID);
    
    IamAccount account = iamAccountRepo.findBySamlId(samlId)
      .orElseThrow(() -> new AssertionError("User not found linked to expected SAML id"));

    assertThat(account.getUsername(), equalTo(TEST_100_USER));

    // Cleanup!
    account.getSamlIds().stream().forEach(i -> i.setAccount(null));
    account.getSamlIds().clear();
    iamAccountRepo.save(account);
  }


  @Test
  @WithMockUser(username = TEST_100_USER)
  public void samlAccountLinkingFailsSinceSamlAccountAlreadyLinkedToAnotherUser() throws Throwable {
    MockHttpSession session = (MockHttpSession) mvc
      .perform(post("/iam/account-linking/SAML").with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/saml/login"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          Matchers.equalTo("/iam/account-linking/SAML")))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get(samlDefaultIdpLoginUrl()).session(session))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        Matchers.equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildTest2Response(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(status().isOk())
      .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, nullValue()))
      .andExpect(forwardedUrl("/iam/account-linking/SAML/done"))
      .andExpect(authenticated().withUsername(TEST_100_USER))
      .andReturn()
      .getRequest()
      .getSession();

    String expectedErrorMessage = String
      .format("SAML account '[%s] (%s = %s)' is already linked to another user", DEFAULT_IDP_ID, 
          EPUID.getAttributeName(),
          T2_EPUID);

    mvc.perform(get("/iam/account-linking/SAML/done").session(session))
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
  public void samlAccountLinkingFailsSinceSamlAccountIsAlreadyBoundToAuthenticatedUser()
      throws Throwable {
    MockHttpSession session = (MockHttpSession) mvc
      .perform(post("/iam/account-linking/SAML").with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/saml/login"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          Matchers.equalTo("/iam/account-linking/SAML")))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get(samlDefaultIdpLoginUrl()).session(session))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        Matchers.equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildTest2Response(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(status().isOk())
      .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, nullValue()))
      .andExpect(forwardedUrl("/iam/account-linking/SAML/done"))
      .andExpect(authenticated().withUsername("test"))
      .andReturn()
      .getRequest()
      .getSession();


    String expectedErrorMessage = String
      .format("SAML account '[%s] (%s = %s)' is already linked to user 'test'", DEFAULT_IDP_ID, 
          EPUID.getAttributeName(),
          T2_EPUID);

    mvc.perform(get("/iam/account-linking/SAML/done").session(session))
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
  public void samlAccountLinkingExternalAuthnErrorRedirectsToDashboard() throws Throwable {
    MockHttpSession session = (MockHttpSession) mvc
      .perform(post("/iam/account-linking/SAML").with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/saml/login"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          Matchers.equalTo("/iam/account-linking/SAML")))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get(samlDefaultIdpLoginUrl()).session(session))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        Matchers.equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildNoAudienceInvalidResponse(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(authenticated().withUsername("test"))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, nullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY, nullValue()))
      .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, notNullValue()))
      .andReturn()
      .getRequest()
      .getSession();
  }

  @Test
  @WithMockUser(username = TEST_100_USER)
  public void samlAccountLinkingUnderstandsIdParam() throws Exception {
    mvc
      .perform(
          post("/iam/account-linking/SAML").param("id", "https://test.idp").with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/saml/login?idp=https://test.idp"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          Matchers.equalTo("/iam/account-linking/SAML")))
      .andReturn()
      .getRequest()
      .getSession();
  }
}
