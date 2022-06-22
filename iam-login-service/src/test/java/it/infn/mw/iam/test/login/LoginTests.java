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


import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.assertNotNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.time.Instant;
import java.util.Date;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class LoginTests implements LoginTestSupport {

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamAupRepository aupRepo;

  @Autowired
  private MockMvc mvc;

  @Test
  public void loginForAdminUserWorks() throws Exception {

    Instant now = Instant.now();

    //@formatter:off
    MockHttpSession session = (MockHttpSession) mvc
      .perform(
          post(LOGIN_URL)
            .param("username", ADMIN_USERNAME)
            .param("password", ADMIN_PASSWORD)
            .param("submit", "Login"))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andReturn()
      .getRequest()
      .getSession();
    //@formatter:on

    mvc.perform(get("/dashboard").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/dashboard"))
      .andReturn();

    IamAccount adminAccount = accountRepo.findByUsername(ADMIN_USERNAME)
      .orElseThrow(() -> new AssertionError("Admin user not found!"));

    assertNotNull(adminAccount.getLastLoginTime());
    assertThat(adminAccount.getLastLoginTime().toInstant(), greaterThan(now));
  }

  @Test
  public void loginWithInvalidCredentialsIsBlocked() throws Exception {
    //@formatter:off
    mvc.perform(post(LOGIN_URL)
        .param("username", ADMIN_USERNAME)
        .param("password", "whatever")
        .param("submit", "Login"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("/login?error=failure"));

    mvc.perform(post(LOGIN_URL)
        .param("username", "whatever")
        .param("password", "whatever")
        .param("submit", "Login"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("/login?error=failure"));
    //@formatter:on
  }

  @Test
  public void loginRedirectsToSignAupPageWhenNeeded() throws Exception {
    IamAup aup = new IamAup();

    aup.setCreationTime(new Date());
    aup.setLastUpdateTime(new Date());
    aup.setName("default-aup");
    aup.setUrl("http://default-aup.org/");
    aup.setDescription("AUP description");
    aup.setSignatureValidityInDays(0L);

    aupRepo.save(aup);

    mvc
      .perform(post(LOGIN_URL).param("username", ADMIN_USERNAME)
        .param("password", ADMIN_PASSWORD)
        .param("submit", "Login"))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/iam/aup/sign"));

  }
}
