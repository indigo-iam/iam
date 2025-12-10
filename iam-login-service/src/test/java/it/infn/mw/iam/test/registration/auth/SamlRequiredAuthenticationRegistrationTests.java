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
package it.infn.mw.iam.test.registration.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {
// @formatter:off
  "iam.registration.requireExternalAuthentication=true",
  "iam.registration.authenticationType=saml",
  "iam.registration.samlEntityId=https://idp.example"
// @formatter:on
})
class SamlRequiredAuthenticationRegistrationTests extends EndpointsTestUtils {

  @Autowired
  private MockOAuth2Filter oauth2Filter;

  @BeforeEach
  void setup() {
    oauth2Filter.cleanupSecurityContext();
  }

  @AfterEach
  void teardown() {
    oauth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithAnonymousUser
  void startRegistrationRequiresAuthentication() throws Exception {
    mvc.perform(get("/start-registration"))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("http://localhost/saml/login?idp=https://idp.example"));
  }
}
