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
package it.infn.mw.iam.test.ext_authn.saml.profile;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.UnsupportedEncodingException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml2.core.AuthnRequest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport;
import it.infn.mw.iam.test.ext_authn.saml.SamlTestConfig;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, SamlTestConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(properties = {
    "saml.custom-profile[0].entityIds=" + SamlAuthenticationTestSupport.DEFAULT_IDP_ID,
    "saml.custom-profile[0].options.spid-idp=true",
    "saml.custom-profile[0].options.spid-authentication-level=SpidL2"})
public class IamSamlEntryPointTests extends SamlAuthenticationTestSupport {

  @Test
  public void testResolution() throws UnsupportedEncodingException, Exception {

    MockHttpSession session = (MockHttpSession) mvc.perform(get(samlDefaultIdpLoginUrl()))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs(), hasSize(1));
    assertThat(authnRequest.getRequestedAuthnContext()
      .getAuthnContextClassRefs()
      .get(0)
      .getAuthnContextClassRef(), is("https://www.spid.gov.it/SpidL2"));

    assertThat(authnRequest.getScoping(), nullValue());
  }
}
