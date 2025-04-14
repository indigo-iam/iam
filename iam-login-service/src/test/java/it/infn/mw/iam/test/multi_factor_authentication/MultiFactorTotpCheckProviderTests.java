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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.BadCredentialsException;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorTotpCheckProvider;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class MultiFactorTotpCheckProviderTests extends IamTotpMfaServiceTestSupport {

  private MultiFactorTotpCheckProvider multiFactorTotpCheckProvider;

  @Mock
  private IamAccountRepository accountRepo;

  @Mock
  private IamTotpMfaService totpMfaService;

  @Mock
  private ExtendedAuthenticationToken token;

  @Mock
  private OidcExternalAuthenticationToken oidcToken;

  @Mock
  private SamlExternalAuthenticationToken samlToken;

  @Before
  public void setup() {
    MockitoAnnotations.openMocks(this);
    multiFactorTotpCheckProvider = new MultiFactorTotpCheckProvider(accountRepo, totpMfaService);
  }

  @Test
  public void authenticateReturnsNullWhenTotpIsNull() {
    when(token.getTotp()).thenReturn(null);
    assertNull(multiFactorTotpCheckProvider.authenticate(token));
  }

  @Test
  public void authenticateThrowsBadCredentialsExceptionWhenAccountNotFound() {
    when(token.getTotp()).thenReturn("123456");
    when(token.getName()).thenReturn("username");
    when(accountRepo.findByUsername("username")).thenReturn(Optional.empty());

    assertThrows(BadCredentialsException.class,
        () -> multiFactorTotpCheckProvider.authenticate(token));
  }

  @Test
  public void authenticatePropagatesMfaSecretNotFoundException() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    when(token.getName()).thenReturn("totp");
    when(token.getTotp()).thenReturn("123456");
    when(accountRepo.findByUsername("totp")).thenReturn(Optional.of(account));
    when(totpMfaService.verifyTotp(account, "123456"))
      .thenThrow(new MfaSecretNotFoundException("Mfa secret not found"));

    assertThrows(MfaSecretNotFoundException.class,
        () -> multiFactorTotpCheckProvider.authenticate(token));
  }

  @Test
  public void authenticateThrowsBadCredentialsExceptionWhenTotpIsInvalid() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    when(token.getName()).thenReturn("totp");
    when(token.getTotp()).thenReturn("123456");
    when(accountRepo.findByUsername(anyString())).thenReturn(Optional.of(account));
    when(totpMfaService.verifyTotp(account, "123456")).thenReturn(false);

    assertThrows(BadCredentialsException.class,
        () -> multiFactorTotpCheckProvider.authenticate(token));
  }

  @Test
  public void authenticateReturnsSuccessfulAuthenticationWhenTotpIsValid() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    when(token.getName()).thenReturn("totp");
    when(token.getTotp()).thenReturn("123456");
    when(accountRepo.findByUsername("totp")).thenReturn(Optional.of(account));
    when(totpMfaService.verifyTotp(account, "123456")).thenReturn(true);

    assertNotNull(multiFactorTotpCheckProvider.authenticate(token));
  }

  @Test
  public void authenticateWithOidcTokenReturnsSuccessfulAuthenticationWhenTotpIsValid() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    when(oidcToken.getName()).thenReturn("totp");
    when(oidcToken.getTotp()).thenReturn("123456");
    when(accountRepo.findByUsername("totp")).thenReturn(Optional.of(account));
    when(totpMfaService.verifyTotp(account, "123456")).thenReturn(true);

    assertNotNull(multiFactorTotpCheckProvider.authenticate(oidcToken));
  }

  @Test
  public void authenticateWithSamlTokenReturnsSuccessfulAuthenticationWhenTotpIsValid() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    when(samlToken.getName()).thenReturn("totp");
    when(samlToken.getTotp()).thenReturn("123456");
    when(accountRepo.findByUsername("totp")).thenReturn(Optional.of(account));
    when(totpMfaService.verifyTotp(account, "123456")).thenReturn(true);

    assertNotNull(multiFactorTotpCheckProvider.authenticate(samlToken));
  }
}
