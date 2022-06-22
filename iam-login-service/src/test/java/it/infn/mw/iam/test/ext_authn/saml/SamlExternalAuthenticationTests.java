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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.saml.SamlUtils;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class SamlExternalAuthenticationTests extends SamlAuthenticationTestSupport {

  @Test
  public void testSuccessfulExternalUnregisteredUserAuthentication() throws Throwable {

    MockHttpSession session =
        (MockHttpSession) mvc.perform(get(samlDefaultIdpLoginUrl()))
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
      .andExpect(redirectedUrl("/")).andReturn().getRequest().getSession();

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
  public void testExternalAuthenticationFailureRedirectsToLoginPage() throws Throwable {

    MockHttpSession session =
        (MockHttpSession) mvc.perform(MockMvcRequestBuilders.get(samlDefaultIdpLoginUrl()))
          .andExpect(MockMvcResultMatchers.status().isOk())
          .andReturn()
          .getRequest()
          .getSession();

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

}
