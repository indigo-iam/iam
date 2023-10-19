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
package it.infn.mw.iam.test.multi_factor_authentication;

import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.WithMockPreAuthenticatedUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class MfaVerifyControllerTests extends MultiFactorTestSupport {

  private MockMvc mvc;

  @Autowired
  private WebApplicationContext context;

  @MockBean
  private IamAccountRepository accountRepository;

  @MockBean
  private IamTotpMfaRepository totpMfaRepository;

  @Before
  public void setup() {
    when(accountRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(TOTP_MFA_ACCOUNT));
    when(totpMfaRepository.findByAccount(TOTP_MFA_ACCOUNT)).thenAnswer(i -> i.getArguments()[0]);

    mvc =
        MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysDo(log()).build();
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testGetVerifyMfaView() throws Exception {
    mvc.perform(get(MFA_VERIFY_URL))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("factors"));

    verify(accountRepository, times(1)).findByUsername(TEST_USERNAME);
    verify(totpMfaRepository, times(1)).findByAccount(TOTP_MFA_ACCOUNT);
  }

  @Test
  @WithAnonymousUser
  public void testGetMfaVerifyViewNoAuthenticationIsUnauthorized() throws Exception {
    mvc.perform(get(MFA_VERIFY_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser
  public void testGetMfaVerifyViewWithFullAuthenticationIsForbidden() throws Exception {
    mvc.perform(get(MFA_VERIFY_URL)).andExpect(status().isForbidden());
  }
}
