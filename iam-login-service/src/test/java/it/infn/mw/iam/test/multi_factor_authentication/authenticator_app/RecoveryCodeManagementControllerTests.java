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
package it.infn.mw.iam.test.multi_factor_authentication.authenticator_app;

import static it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app.RecoveryCodeManagementController.RECOVERY_CODE_GET_URL;
import static it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app.RecoveryCodeManagementController.RECOVERY_CODE_RESET_URL;
import static it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app.RecoveryCodeManagementController.RECOVERY_CODE_VIEW_URL;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.AuthenticationException;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpRecoveryCodeResetService;
import it.infn.mw.iam.persistence.model.IamTotpRecoveryCode;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.multi_factor_authentication.MultiFactorTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.WithMockMfaUser;
import it.infn.mw.iam.test.util.WithMockPreAuthenticatedUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class RecoveryCodeManagementControllerTests extends MultiFactorTestSupport {

  private MockMvc mvc;

  @Autowired
  private WebApplicationContext context;

  @MockBean
  private IamTotpMfaRepository totpMfaRepository;

  @MockBean
  private AccountUtils accountUtils;

  @MockBean
  private IamTotpRecoveryCodeResetService service;

  @MockBean
  private ApplicationEventPublisher eventPublisher;

  @MockBean
  private RecoveryCodeGenerator generator;

  @Captor
  private ArgumentCaptor<ApplicationEvent> authEventCaptor;

  @Captor
  private ArgumentCaptor<AuthenticationException> authExceptionCaptor;

  @Before
  public void setup() {
    when(accountUtils.getAuthenticatedUserAccount()).thenReturn(Optional.of(TOTP_MFA_ACCOUNT));
    when(totpMfaRepository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(TOTP_MFA));
    when(service.resetRecoveryCodes(TOTP_MFA_ACCOUNT)).thenAnswer(i -> i.getArguments()[0]);

    mvc =
        MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysDo(log()).build();
  }

  @After
  public void tearDown() {
    reset(accountUtils);
    reset(service);
    reset(eventPublisher);

    resetTestAccount();
  }

  @Test
  @WithMockMfaUser
  public void testGetResetView() throws Exception {
    mvc.perform(get(RECOVERY_CODE_RESET_URL)).andExpect(status().isOk());
  }

  @Test
  @WithAnonymousUser
  public void testGetResetViewNoAuthenticationFails() throws Exception {
    mvc.perform(get(RECOVERY_CODE_RESET_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testGetResetViewWithPreAuthenticationFails() throws Exception {
    mvc.perform(get(RECOVERY_CODE_RESET_URL)).andExpect(status().isUnauthorized());
  }

  // TODO test getResetView with user that doesn't have MFA enabled. Currently, I don't think the
  // user is forbidden in this case

  @Test
  @WithMockMfaUser
  public void testPutResetAddsNewCodes() throws Exception {
    mvc.perform(put(RECOVERY_CODE_RESET_URL)).andExpect(status().isOk());
    verify(service, times(1)).resetRecoveryCodes(TOTP_MFA_ACCOUNT);
  }

  @Test
  @WithAnonymousUser
  public void testPutResetNoAuthenticationFails() throws Exception {
    mvc.perform(put(RECOVERY_CODE_RESET_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testPutResetWithPreAuthenticationFails() throws Exception {
    mvc.perform(put(RECOVERY_CODE_RESET_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockMfaUser
  public void testViewRecoveryCodes() throws Exception {
    mvc.perform(get(RECOVERY_CODE_VIEW_URL))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("recoveryCodes"));
  }

  @Test
  @WithAnonymousUser
  public void testViewRecoveryCodesNoAuthenticationFails() throws Exception {
    mvc.perform(get(RECOVERY_CODE_VIEW_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testViewRecoveryCodesWithPreAuthenticationFails() throws Exception {
    mvc.perform(get(RECOVERY_CODE_VIEW_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockMfaUser
  public void testGetRecoveryCodes() throws Exception {
    MvcResult result =
        mvc.perform(get(RECOVERY_CODE_GET_URL)).andExpect(status().isOk()).andReturn();

    String content = result.getResponse().getContentAsString();
    content = content.substring(1, content.length() - 1);
    String[] arr = content.split(",");

    String[] originalCodes = new String[RECOVERY_CODE_SET_FIRST.size()];
    List<IamTotpRecoveryCode> recoveryCodes = new ArrayList<>(RECOVERY_CODE_SET_FIRST);
    for (int i = 0; i < recoveryCodes.size(); i++) {
      originalCodes[i] = recoveryCodes.get(i).getCode();

      // This is here because the string.split() method adds backslashed quotes around the separated
      // strings. So this is a hacky method to remove them to allow for the comparison to succeed.
      arr[i] = arr[i].substring(1, arr[i].length() - 1);
    }
    assertThat(originalCodes, equalTo(arr));
  }

  @Test
  @WithAnonymousUser
  public void testGetRecoveryCodesNoAuthenticationFails() throws Exception {
    mvc.perform(get(RECOVERY_CODE_GET_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testGetRecoveryCodesWithPreAuthenticationFails() throws Exception {
    mvc.perform(get(RECOVERY_CODE_GET_URL)).andExpect(status().isUnauthorized());
  }
}
