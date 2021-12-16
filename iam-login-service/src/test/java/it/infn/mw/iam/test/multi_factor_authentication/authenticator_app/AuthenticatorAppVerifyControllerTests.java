package it.infn.mw.iam.test.multi_factor_authentication.authenticator_app;

import static it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app.AuthenticatorAppVerifyController.VERIFY_CODE_URL;
import static it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app.AuthenticatorAppVerifyController.VERIFY_RECOVERY_CODE_URL;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
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
import org.mockito.InjectMocks;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import dev.samstevens.totp.code.CodeVerifier;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app.AuthenticatorAppVerifyController;
import it.infn.mw.iam.authn.multi_factor_authentication.error.MultiFactorAuthenticationError;
import it.infn.mw.iam.core.user.DefaultIamAccountService;
import it.infn.mw.iam.test.multi_factor_authentication.MultiFactorTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.WithMockPreAuthenticatedUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class AuthenticatorAppVerifyControllerTests extends MultiFactorTestSupport {

  private MockMvc mvc;

  @Autowired
  private WebApplicationContext context;

  @MockBean
  private AccountUtils accountUtils;

  @MockBean
  private CodeVerifier codeVerifier;

  @MockBean
  private DefaultIamAccountService service;

  @MockBean
  private AuthenticationEventPublisher eventPublisher;

  @Captor
  private ArgumentCaptor<Authentication> authEventCaptor;

  @Captor
  private ArgumentCaptor<AuthenticationException> authExceptionCaptor;

  @InjectMocks
  private AuthenticatorAppVerifyController controller;

  @Before
  public void setup() {
    when(accountUtils.getAuthenticatedUserAccount()).thenReturn(Optional.of(TEST_ACCOUNT));
    when(codeVerifier.isValidCode(anyString(), anyString())).thenReturn(true);

    mvc =
        MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysDo(log()).build();
  }

  @After
  public void tearDown() {
    reset(accountUtils);
    reset(codeVerifier);
  }

  @Test
  @WithMockPreAuthenticatedUser(username = TEST_USERNAME)
  public void testVerifyCodeValidCode() throws Exception {
    mvc
      .perform(post(VERIFY_CODE_URL).param("code", "123456")
        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
      .andExpect(status().is3xxRedirection());

    verify(eventPublisher).publishAuthenticationSuccess(authEventCaptor.capture());
    Authentication newAuth = authEventCaptor.getValue();
    List<GrantedAuthority> authorities = new ArrayList<>(newAuth.getAuthorities());
    assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_USER")));
  }

  @Test
  @WithMockPreAuthenticatedUser(username = TEST_USERNAME)
  public void testVerifyCodeWrongCodeFails() throws Exception {
    when(codeVerifier.isValidCode(anyString(), anyString())).thenReturn(false);

    mvc
      .perform(post(VERIFY_CODE_URL).param("code", "123456")
        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
      .andExpect(status().is3xxRedirection());

    verify(eventPublisher).publishAuthenticationFailure(authExceptionCaptor.capture(), any());
    AuthenticationException e = authExceptionCaptor.getValue();
    assertThat(e, instanceOf(MultiFactorAuthenticationError.class));
    assertEquals(e.getMessage(), "Bad MFA code");
  }

  @Test
  @WithMockPreAuthenticatedUser(username = TEST_USERNAME)
  public void testVerifyCodeInvalidCodeFormatFails() throws Exception {
    mvc
      .perform(post(VERIFY_CODE_URL).param("code", "invalid-code")
        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
      .andExpect(status().is3xxRedirection());

    verify(eventPublisher).publishAuthenticationFailure(authExceptionCaptor.capture(), any());
    AuthenticationException e = authExceptionCaptor.getValue();
    assertThat(e, instanceOf(MultiFactorAuthenticationError.class));
    assertEquals(e.getMessage(), "Bad MFA code");
  }

  @Test
  @WithAnonymousUser
  public void testVerifyCodeNoPreAuthenticationFails() throws Exception {
    mvc
      .perform(post(VERIFY_CODE_URL).param("code", "123456")
        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
      .andExpect(status().is4xxClientError());
  }

  @Test
  @WithMockPreAuthenticatedUser(username = TEST_USERNAME)
  public void testVerifyRecoveryCodeValidRecoveryCode() throws Exception {
    mvc
      .perform(post(VERIFY_RECOVERY_CODE_URL).param("recoveryCode", TOTP_RECOVERY_CODE_1.getCode())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
      .andExpect(status().is3xxRedirection());

    verify(eventPublisher).publishAuthenticationSuccess(authEventCaptor.capture());
    Authentication newAuth = authEventCaptor.getValue();
    List<GrantedAuthority> authorities = new ArrayList<>(newAuth.getAuthorities());
    assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_USER")));
  }

  @Test
  @WithMockPreAuthenticatedUser(username = TEST_USERNAME)
  public void testVerifyRecoveryCodeEmptyRecoveryCodeFails() throws Exception {
    mvc
      .perform(post(VERIFY_RECOVERY_CODE_URL).param("recoveryCode", "")
        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
      .andExpect(status().is3xxRedirection());

    verify(eventPublisher).publishAuthenticationFailure(authExceptionCaptor.capture(), any());
    AuthenticationException e = authExceptionCaptor.getValue();
    assertThat(e, instanceOf(MultiFactorAuthenticationError.class));
    assertEquals(e.getMessage(), "Bad recovery code");
  }

  @Test
  @WithMockPreAuthenticatedUser(username = TEST_USERNAME)
  public void testVerifyRecoveryCodeWrongRecoveryCodeFails() throws Exception {
    mvc
      .perform(post(VERIFY_RECOVERY_CODE_URL).param("recoveryCode", "wrong-code")
        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
      .andExpect(status().is3xxRedirection());

    verify(eventPublisher).publishAuthenticationFailure(authExceptionCaptor.capture(), any());
    AuthenticationException e = authExceptionCaptor.getValue();
    assertThat(e, instanceOf(MultiFactorAuthenticationError.class));
    assertEquals(e.getMessage(), "Bad recovery code");
  }

  @Test
  @WithAnonymousUser
  public void testVerifyRecoveryCodeNoPreAuthenticationFails() throws Exception {
    mvc
      .perform(post(VERIFY_RECOVERY_CODE_URL).param("recoveryCode", TOTP_RECOVERY_CODE_1.getCode())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
      .andExpect(status().is4xxClientError());
  }
}
