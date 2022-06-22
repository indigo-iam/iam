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
package it.infn.mw.iam.test.registration;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTH_ERROR_KEY;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.DisabledException;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport;
import it.infn.mw.iam.test.util.WithMockSAMLUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.saml.SamlUtils;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class SamlExtAuthRegistrationTests extends SamlAuthenticationTestSupport {

  @Autowired
  private IamAccountRepository iamAccountRepo;

  @Autowired
  private PersistentUUIDTokenGenerator generator;

  @Test
  @WithMockSAMLUser(issuer = DEFAULT_IDP_ID, subject = T1_EPUID)
  public void externalSamlRegistrationCreatesDisabledAccount() throws Throwable {

    String username = "test-saml-ext-reg";

    String email = username + "@example.org";
    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("Saml User");
    request.setEmail(email);
    request.setUsername(username);
    request.setNotes("Some short notes...");

    byte[] requestBytes = mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsBytes(request)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    request = objectMapper.readValue(requestBytes, RegistrationRequestDto.class);
    String token = generator.getLastToken();

    // If the user tries to authenticate with his external account, he's redirected to the
    // login page with an account disabled error
    MockHttpSession session = (MockHttpSession) mvc.perform(get(samlDefaultIdpLoginUrl()))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);
    Response r = buildTest1Response(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrlPattern("/login**"))
      .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, notNullValue()))
      .andReturn()
      .getRequest()
      .getSession();

    assertThat(session.getAttribute(EXT_AUTH_ERROR_KEY), instanceOf(DisabledException.class));

    DisabledException err = (DisabledException) session.getAttribute(EXT_AUTH_ERROR_KEY);
    assertThat(err.getMessage(),
        startsWith("Your registration request to indigo-dc was submitted successfully"));

    // the same happens after having confirmed the request
    mvc.perform(get("/registration/confirm/{token}", token)).andExpect(status().isOk());

    session = (MockHttpSession) mvc.perform(get(samlDefaultIdpLoginUrl()))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    authnRequest = getAuthnRequestFromSession(session);
    r = buildTest1Response(authnRequest);
    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrlPattern("/login**"))
      .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, notNullValue()))
      .andReturn()
      .getRequest()
      .getSession();

    assertThat(session.getAttribute(EXT_AUTH_ERROR_KEY), instanceOf(DisabledException.class));
    err = (DisabledException) session.getAttribute(EXT_AUTH_ERROR_KEY);
    assertThat(err.getMessage(), startsWith(
        "Your registration request to indigo-dc was submitted and confirmed successfully"));

    IamSamlId id = new IamSamlId(DEFAULT_IDP_ID, Saml2Attribute.EPUID.getAttributeName(), T1_EPUID);

    IamAccount account = iamAccountRepo.findBySamlId(id)
      .orElseThrow(() -> new AssertionError("Expected account not found"));

    iamAccountRepo.delete(account);
  }
}
