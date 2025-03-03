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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.mitre.openid.connect.model.UserInfo;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.oidc.service.JustInTimeProvisioningOIDCUserDetailsService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@RunWith(MockitoJUnitRunner.class)
public class OidcJitAccountProvisioningTests {

  @Mock
  private IamAccountRepository repo;

  @Mock
  private InactiveAccountAuthenticationHander handler;

  @Mock
  private IamAccountService accountService;

  private Optional<Set<String>> trustedIdpEntityIds;

  @InjectMocks
  private JustInTimeProvisioningOIDCUserDetailsService service;

  @Before
  public void setup() {
    MockitoAnnotations.openMocks(this);
    trustedIdpEntityIds = Optional.of(Set.of("https://trusted-idp.com"));
    service = new JustInTimeProvisioningOIDCUserDetailsService(repo, handler, accountService,
        trustedIdpEntityIds);
  }

  @Test
  public void loadUserByOIDCTokenReturnsUserIfAlreadyExists() {

    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);
    when(token.getIssuer()).thenReturn("https://trusted-idp.com");
    when(token.getSub()).thenReturn("sub123");

    IamAccount existingAccount = new IamAccount();
    existingAccount.setUsername("jsdoe");
    existingAccount.setActive(true);
    existingAccount.setPassword("secret");
    when(repo.findByOidcId("https://trusted-idp.com", "sub123"))
      .thenReturn(Optional.of(existingAccount));

    Object user = service.loadUserByOIDC(token);

    assertNotNull(user);
    verify(repo).findByOidcId("https://trusted-idp.com", "sub123");
  }

  @Test
  public void loadUserByOIDCTokenProvisioningOccurs() {

    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);
    when(token.getIssuer()).thenReturn("https://trusted-idp.com");
    when(token.getSub()).thenReturn("sub123");

    UserInfo userInfo = mock(UserInfo.class);
    when(token.getUserInfo()).thenReturn(userInfo);

    when(userInfo.getGivenName()).thenReturn("John");
    when(userInfo.getFamilyName()).thenReturn("Doe");
    when(userInfo.getEmail()).thenReturn("john.doe@example.com");

    when(repo.findByOidcId("https://trusted-idp.com", "sub123")).thenReturn(Optional.empty());

    doAnswer(invocation -> {
      IamAccount account = invocation.getArgument(0);
      account.setPassword("securePassword123");
      return account;
    }).when(accountService).createAccount(any(IamAccount.class));

    Object user = service.loadUserByOIDC(token);

    assertNotNull(user);
    verify(accountService).createAccount(any(IamAccount.class));
  }


  @Test
  public void loadUserByOIDCUntrustedIdpThrowsException() {

    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);
    when(token.getIssuer()).thenReturn("https://untrusted-idp.com");

    assertThrows(UsernameNotFoundException.class, () -> service.loadUserByOIDC(token));
  }

  @Test
  public void loadUserByOIDCMissingClaimsThrowsException() {

    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);
    when(token.getIssuer()).thenReturn("https://trusted-idp.com");
    when(token.getUserInfo()).thenReturn(mock(UserInfo.class));

    UserInfo userInfo = token.getUserInfo();
    when(userInfo.getGivenName()).thenReturn(null);

    assertThrows(UsernameNotFoundException.class, () -> service.loadUserByOIDC(token));
  }
}
