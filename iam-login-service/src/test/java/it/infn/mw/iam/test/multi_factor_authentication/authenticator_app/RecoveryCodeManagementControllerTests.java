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

import static it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app.RecoveryCodeManagementController.GET_URL;
import static it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app.RecoveryCodeManagementController.RESET_URL;
import static it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app.RecoveryCodeManagementController.VIEW_URL;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.RecoveryCodesResetEvent;
import it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app.AuthenticatorAppVerifyController;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpRecoveryCode;
import it.infn.mw.iam.test.multi_factor_authentication.MultiFactorTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.WithMockPreAuthenticatedUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class RecoveryCodeManagementControllerTests extends MultiFactorTestSupport {

  private MockMvc mvc;

  @Autowired
  private WebApplicationContext context;

  @MockBean
  private AccountUtils accountUtils;

  @MockBean
  private IamAccountService service;

  @MockBean
  private ApplicationEventPublisher eventPublisher;

  @Captor
  private ArgumentCaptor<ApplicationEvent> authEventCaptor;

  @Captor
  private ArgumentCaptor<AuthenticationException> authExceptionCaptor;

  @InjectMocks
  private AuthenticatorAppVerifyController controller;

  @Before
  public void setup() {
    when(accountUtils.getAuthenticatedUserAccount()).thenReturn(Optional.of(TEST_ACCOUNT));
    when(service.addTotpMfaRecoveryCodes(TEST_ACCOUNT)).thenAnswer(i -> i.getArguments()[0]);
    when(service.saveAccount(TEST_ACCOUNT)).thenAnswer(i -> i.getArguments()[0]);

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
  @WithMockUser
  public void testGetResetView() throws Exception {
    mvc.perform(get(RESET_URL)).andExpect(status().isOk());
  }

  @Test
  @WithAnonymousUser
  public void testGetResetViewNoAuthenticationFails() throws Exception {
    mvc.perform(get(RESET_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testGetResetViewWithPreAuthenticationFails() throws Exception {
    mvc.perform(get(RESET_URL)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testPostResetRedirectsAndAddsNewCodes() throws Exception {
    TEST_ACCOUNT.getTotpMfa().setRecoveryCodes(RECOVERY_CODE_SET_SECOND);
    mvc.perform(post(RESET_URL)).andExpect(status().is3xxRedirection());

    verify(eventPublisher).publishEvent(authEventCaptor.capture());
    ApplicationEvent e = authEventCaptor.getValue();
    assertThat(e, instanceOf(RecoveryCodesResetEvent.class));
  }

  @Test
  @WithAnonymousUser
  public void testPostResetNoAuthenticationFails() throws Exception {
    mvc.perform(post(RESET_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testPostResetWithPreAuthenticationFails() throws Exception {
    mvc.perform(post(RESET_URL)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = TEST_USERNAME)
  public void testPutResetAddsNewCodes() throws Exception {

    // Duplicate original recovery codes for comparison later on
    Set<IamTotpRecoveryCode> originalSet = new HashSet<>(RECOVERY_CODE_SET_FIRST);

    // Duplicate original account to be returned from authentication
    IamAccount originalAccount = cloneAccount(TEST_ACCOUNT);
    when(accountUtils.getAuthenticatedUserAccount()).thenReturn(Optional.of(originalAccount));

    // An account with new codes is returned. This demonstrates the generation of new codes
    TEST_ACCOUNT.getTotpMfa().setRecoveryCodes(RECOVERY_CODE_SET_SECOND);
    when(service.addTotpMfaRecoveryCodes(any())).thenReturn(TEST_ACCOUNT);
    when(service.saveAccount(any())).thenReturn(TEST_ACCOUNT);

    mvc.perform(put(RESET_URL)).andExpect(status().isOk());

    verify(eventPublisher).publishEvent(authEventCaptor.capture());
    ApplicationEvent e = authEventCaptor.getValue();
    assertThat(e, instanceOf(RecoveryCodesResetEvent.class));

    RecoveryCodesResetEvent recoveryCodeEvent = (RecoveryCodesResetEvent) e;
    Set<IamTotpRecoveryCode> recoveryCodes =
        recoveryCodeEvent.getAccount().getTotpMfa().getRecoveryCodes();
    assertThat(recoveryCodes.toArray(), not(equalTo(originalSet.toArray())));
  }

  @Test
  @WithAnonymousUser
  public void testPutResetNoAuthenticationFails() throws Exception {
    mvc.perform(post(RESET_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testPutResetWithPreAuthenticationFails() throws Exception {
    mvc.perform(post(RESET_URL)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser
  public void testViewRecoveryCodes() throws Exception {
    mvc.perform(get(VIEW_URL))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("recoveryCodes"));
  }

  @Test
  @WithAnonymousUser
  public void testViewRecoveryCodesNoAuthenticationFails() throws Exception {
    mvc.perform(get(VIEW_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testViewRecoveryCodesWithPreAuthenticationFails() throws Exception {
    mvc.perform(get(VIEW_URL)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser
  public void testGetRecoveryCodes() throws Exception {
    MvcResult result = mvc.perform(get(GET_URL)).andExpect(status().isOk()).andReturn();

    String content = result.getResponse().getContentAsString();
    content = content.substring(1, content.length() - 1);
    String[] arr = content.split(",");

    String[] err = new String[RECOVERY_CODE_SET_FIRST.size()];
    List<IamTotpRecoveryCode> recoveryCodes = new ArrayList<>(RECOVERY_CODE_SET_FIRST);
    for (int i = 0; i < recoveryCodes.size(); i++) {
      err[i] = recoveryCodes.get(i).getCode();

      // This is here because the string.split() method adds backslashed quotes around the separated
      // strings. So this is a hacky method to remove them to allow for the comparison to succeed.
      arr[i] = arr[i].substring(1, arr[i].length() - 1);
    }
    assertThat(err, equalTo(arr));
  }

  @Test
  @WithAnonymousUser
  public void testGetRecoveryCodesNoAuthenticationFails() throws Exception {
    mvc.perform(get(GET_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockPreAuthenticatedUser
  public void testGetRecoveryCodesWithPreAuthenticationFails() throws Exception {
    mvc.perform(get(GET_URL)).andExpect(status().isForbidden());
  }
}
