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
package it.infn.mw.iam.test.login;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"iam.local-authn.enabled-for=vo-admins"})
public class LoginEnabledOnlyForAdminsTests implements LoginTestSupport {

  @Autowired
  private MockMvc mvc;

  @Test
  public void loginForAdminUserWorks() throws Exception {
    mvc
      .perform(post(LOGIN_URL).param("username", ADMIN_USERNAME)
        .param("password", ADMIN_PASSWORD)
        .param("submit", "Login"))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"));
  }

  @Test
  public void loginForUnprivilegedUserFails() throws Exception {
    MockHttpSession session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", USER_USERNAME)
        .param("password", USER_PASSWORD)
        .param("submit", "Login"))
      .andExpect(unauthenticated())
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("/login?error=failure"))
      .andReturn()
      .getRequest()
      .getSession();

    AuthenticationException ae =
        (AuthenticationException) session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    
    assertThat(ae.getMessage(), is(DISABLED_AUTH_MSG));
  }

}
