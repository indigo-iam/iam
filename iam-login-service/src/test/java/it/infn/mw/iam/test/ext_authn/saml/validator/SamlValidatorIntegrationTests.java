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
package it.infn.mw.iam.test.ext_authn.saml.validator;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTH_ERROR_KEY;
import static it.infn.mw.iam.authn.saml.validator.check.SamlHasAttributeCheck.hasAttribute;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Optional;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.common.ValidatorError;
import it.infn.mw.iam.authn.common.ValidatorResolver;
import it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.saml.SamlUtils;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, SamlValidatorIntegrationTests.TestConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@WebAppConfiguration
public class SamlValidatorIntegrationTests extends SamlAuthenticationTestSupport {

  @TestConfiguration
  public static class TestConfig {

    @Bean
    @Primary
    ValidatorResolver<SAMLCredential> validatorResolver() {
      return r -> Optional.of(hasAttribute("1.2.3.4"));
    }

  }

  @Test
  public void testValidatorFailure() throws Throwable {
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
        .andExpect(redirectedUrlPattern("/login**"))
        .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, instanceOf(ValidatorError.class)))
        .andReturn()
        .getRequest()
        .getSession();
  }


}
