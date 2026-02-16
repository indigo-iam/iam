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
package it.infn.mw.iam.test.ext_authn.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.InternalAuthenticationServiceException;

import it.infn.mw.iam.authn.oidc.model.OIDCAuthenticationToken;
import it.infn.mw.iam.authn.oidc.provisioning.OidcAccountProvisioningService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@ExtendWith(MockitoExtension.class)
class OidcJitAccountProvisioningTests {

  @Mock
  private IamAccountRepository repo;

  @Mock
  private IamAccountService accountService;

  private Optional<Set<String>> trustedIdpEntityIds;

  @InjectMocks
  private OidcAccountProvisioningService service;

  @BeforeEach
  void setup() {
    MockitoAnnotations.openMocks(this);
    trustedIdpEntityIds = Optional.of(Set.of("https://trusted-idp.com"));
    service = new OidcAccountProvisioningService(repo, accountService, trustedIdpEntityIds);
  }

  @Test
  void provisionAccountWithValidTokenAndAvailableUsernameCreatesNewAccount() {
    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);
    IamUserInfo userInfo = mock(IamUserInfo.class);

    when(token.getIssuer()).thenReturn("https://trusted-idp.com");
    when(token.getSub()).thenReturn("sub123");
    when(token.getUserInfo()).thenReturn(userInfo);
    when(userInfo.getGivenName()).thenReturn("John");
    when(userInfo.getFamilyName()).thenReturn("Doe");
    when(userInfo.getEmail()).thenReturn("john.doe@example.com");
    when(userInfo.getPreferredUsername()).thenReturn("jdoe");

    when(repo.findByUsername("jdoe")).thenReturn(Optional.empty());

    IamAccount savedAccount = new IamAccount();
    when(accountService.createAccount(any())).thenReturn(savedAccount);

    IamAccount result = service.provisionAccount(token);

    assertNotNull(result);
    verify(accountService).createAccount(any(IamAccount.class));
    verify(repo).findByUsername("jdoe");
  }

  @Test
  void provisionAccountWhenAccountNotFoundPerformsJustInTimeProvisioning() {
    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);
    when(token.getIssuer()).thenReturn("https://trusted-idp.com");
    when(token.getSub()).thenReturn("sub123");

    IamUserInfo userInfo = mock(IamUserInfo.class);
    when(token.getUserInfo()).thenReturn(userInfo);

    when(userInfo.getGivenName()).thenReturn("John");
    when(userInfo.getFamilyName()).thenReturn("Doe");
    when(userInfo.getEmail()).thenReturn("john.doe@example.com");

    doAnswer(invocation -> {
      IamAccount account = invocation.getArgument(0);
      account.setPassword("securePassword123");
      return account;
    }).when(accountService).createAccount(any(IamAccount.class));

    IamAccount result = service.provisionAccount(token);

    assertNotNull(result);
    verify(accountService).createAccount(any(IamAccount.class));
  }

  @Test
  void provisionAccountUsesPreferredUsernameWhenAvailable() {
    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);
    when(token.getIssuer()).thenReturn("https://trusted-idp.com");
    when(token.getSub()).thenReturn("sub123");

    IamUserInfo userInfo = mock(IamUserInfo.class);
    when(token.getUserInfo()).thenReturn(userInfo);
    when(userInfo.getGivenName()).thenReturn("John");
    when(userInfo.getFamilyName()).thenReturn("Doe");
    when(userInfo.getEmail()).thenReturn("john.doe@example.com");
    when(userInfo.getPreferredUsername()).thenReturn("johndoe");

    when(repo.findByUsername("johndoe")).thenReturn(Optional.empty());

    doAnswer(invocation -> {
      IamAccount account = invocation.getArgument(0);
      account.setPassword("securePassword123");
      assertEquals("johndoe", account.getUsername());
      return account;
    }).when(accountService).createAccount(any(IamAccount.class));

    IamAccount result = service.provisionAccount(token);

    assertNotNull(result);
    verify(accountService).createAccount(any(IamAccount.class));
  }

  @Test
  void provisionAccountUsesRandomUUIDWhenPreferredUsernameUnavailable() {
    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);
    when(token.getIssuer()).thenReturn("https://trusted-idp.com");
    when(token.getSub()).thenReturn("sub123");

    IamUserInfo userInfo = mock(IamUserInfo.class);
    when(token.getUserInfo()).thenReturn(userInfo);
    when(userInfo.getGivenName()).thenReturn("John");
    when(userInfo.getFamilyName()).thenReturn("Doe");
    when(userInfo.getEmail()).thenReturn("john.doe@example.com");
    when(userInfo.getPreferredUsername()).thenReturn("johndoe");

    when(repo.findByUsername("johndoe")).thenReturn(Optional.of(mock(IamAccount.class)));

    doAnswer(invocation -> {
      IamAccount account = invocation.getArgument(0);
      account.setPassword("securePassword123");
      return account;
    }).when(accountService).createAccount(any(IamAccount.class));

    IamAccount result = service.provisionAccount(token);

    assertNotNull(result);
    verify(accountService).createAccount(any(IamAccount.class));
  }

  @Test
  void provisionAccountThrowsExceptionWhenIdpIsUntrusted() {

    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);
    when(token.getIssuer()).thenReturn("https://untrusted-idp.com");

    assertThrows(InternalAuthenticationServiceException.class, () -> service.provisionAccount(token));
  }

  @Test
  void provisionAccountThrowsExceptionWhenEmailIsAlreadyBound() {

    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);
    when(token.getIssuer()).thenReturn("https://trusted-idp.com");
    IamUserInfo userInfo = mock(IamUserInfo.class);
    when(userInfo.getGivenName()).thenReturn("Already");
    when(userInfo.getFamilyName()).thenReturn("Bound");
    when(userInfo.getEmail()).thenReturn("test@iam.test");
    when(token.getUserInfo()).thenReturn(userInfo);

    when(repo.findByEmail("test@iam.test")).thenReturn(Optional.of(mock(IamAccount.class)));

    assertThrows(InternalAuthenticationServiceException.class, () -> service.provisionAccount(token));
  }

  @Test
  void provisionAccountThrowsExceptionWhenRequiredClaimsAreMissing() {

    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);
    when(token.getIssuer()).thenReturn("https://trusted-idp.com");
    when(token.getUserInfo()).thenReturn(mock(IamUserInfo.class));

    IamUserInfo userInfo = token.getUserInfo();
    when(userInfo.getGivenName()).thenReturn(null);

    assertThrows(InternalAuthenticationServiceException.class, () -> service.provisionAccount(token));

    when(userInfo.getGivenName()).thenReturn("John");
    when(userInfo.getFamilyName()).thenReturn(null);

    assertThrows(InternalAuthenticationServiceException.class, () -> service.provisionAccount(token));

    when(userInfo.getFamilyName()).thenReturn("Doe");
    when(userInfo.getEmail()).thenReturn(null);

    assertThrows(InternalAuthenticationServiceException.class, () -> service.provisionAccount(token));
  }
}
