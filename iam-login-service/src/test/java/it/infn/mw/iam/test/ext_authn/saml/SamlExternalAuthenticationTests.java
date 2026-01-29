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
package it.infn.mw.iam.test.ext_authn.saml;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTH_ERROR_KEY;
import static it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType.SAML;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.Date;
import java.util.random.RandomGenerator;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.saml.SamlUtils;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
class SamlExternalAuthenticationTests extends SamlAuthenticationTestSupport {

  @Autowired
  private IamAupRepository aupRepo;
  
  private static final String URL_DASHBOARD = "/dashboard";
  private static final String URL_VERIFY = "/iam/verify";
  private static final String VIEW_VERIFY_MFA = "iam/verify-mfa";


  @Test
  void testSuccessfulExternalUnregisteredUserAuthentication() throws Throwable {

    MockHttpSession session = performInitialLogin();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        Matchers.equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildTest1Response(authnRequest);

    session = (MockHttpSession) mvc.perform(post(authnRequest.getAssertionConsumerServiceURL())
      .contentType(MediaType.APPLICATION_FORM_URLENCODED)
      .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
      .session(session)).andExpect(redirectedUrl("/")).andReturn().getRequest().getSession();

    mvc.perform(get("/").session(session))
      .andExpect(status().isOk())
      .andExpect(forwardedUrl("/start-registration"));

    mvc.perform(get(EXT_AUTHN_URL).session(session))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.given_name").value(equalTo(T1_GIVEN_NAME)))
      .andExpect(jsonPath("$.family_name").value(equalTo(T1_SN)))
      .andExpect(jsonPath("$.email").value(equalTo(T1_MAIL)))
      .andExpect(jsonPath("$.type").value(equalTo(SAML.name())))
      .andExpect(jsonPath("$.issuer").value(equalTo(DEFAULT_IDP_ID)))
      .andExpect(jsonPath("$.subject").value(equalTo(T1_EPUID)))
      .andExpect(jsonPath("$.suggested_username").value(equalTo(T1_EPPN)));
  }

  @Test
  void testExternalAuthenticationFailureRedirectsToLoginPage() throws Throwable {

    MockHttpSession session = performInitialLogin();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        Matchers.equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildNoAttributesInvalidResponse(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(redirectedUrlPattern("/login**"))
      .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, notNullValue()))
      .andReturn()
      .getRequest()
      .getSession();
  }

  @Test
  void testRegisteredUserWithMfaGetsRedirectedToMfaVerify() throws Throwable {

    MockHttpSession session = performInitialLogin();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);
    Response response = buildMfaTest1Response(authnRequest);
    session = postMfaResponseAndExpectRedirect(response, authnRequest, session, URL_VERIFY);

    mvc.perform(get(URL_VERIFY).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name(VIEW_VERIFY_MFA));
  }

  @Test
  void testRedirectionToDashboardIfRemoteIdpPerformsMfa() throws Throwable {

    MockHttpSession session = performInitialLogin();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    Response response = buildMfaTest2Response(authnRequest);
    postMfaResponseAndExpectRedirect(response, authnRequest, session, URL_DASHBOARD);
  }

  @Test
  void testRegisteredUserWithMfaGetsRedirectedToMfaVerifyEvenIfAupPending() throws Throwable {
    createDefaultAup();
    MockHttpSession session = performInitialLogin();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);
    Response response = buildMfaTest1Response(authnRequest);
    session = postMfaResponseAndExpectRedirect(response, authnRequest, session, URL_VERIFY);

    mvc.perform(get(URL_VERIFY).session(session))
        .andExpect(status().isOk())
        .andExpect(view().name(VIEW_VERIFY_MFA));
    
    aupRepo.deleteAll();    
  }

  private MockHttpSession performInitialLogin() throws Exception {
    return (MockHttpSession) mvc.perform(get(samlDefaultIdpLoginUrl()))
        .andExpect(status().isOk())
        .andReturn()
        .getRequest()
        .getSession();
  }

  private MockHttpSession postMfaResponseAndExpectRedirect(Response response, AuthnRequest authnRequest,
      MockHttpSession session, String expectedUrl) throws Throwable {
    String encodedSaml = SamlUtils.signAndSerializeToBase64(response);

    return (MockHttpSession) mvc.perform(
        post(authnRequest.getAssertionConsumerServiceURL())
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .param("SAMLResponse", encodedSaml)
            .session(session))
        .andExpect(redirectedUrl(expectedUrl))
        .andReturn()
        .getRequest()
        .getSession();
  }

  private void createDefaultAup() {
    IamAup aup = new IamAup();

    aup.setCreationTime(new Date());
    aup.setLastUpdateTime(new Date());
    aup.setName("default-aup" + RandomGenerator.getDefault().nextInt());
    aup.setUrl("http://default-aup.org/");
    aup.setDescription("AUP description");
    aup.setSignatureValidityInDays(0L);
    aup.setAupRemindersInDays("30,15,1");

    aupRepo.saveDefaultAup(aup);
  }
}
