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

package it.infn.mw.iam.test.authn.x509;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationUserDetailService;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;

@ExtendWith(MockitoExtension.class)
class IamX509AuthenticationUserDetailServiceTests extends X509TestSupport {

  @Mock
  IamAccountRepository accountRepository;
  @Mock
  IamTotpMfaRepository totpMfaRepository;
  @Mock
  InactiveAccountAuthenticationHander inactiveAccountHandler;
  @Mock
  IamTotpMfaProperties iamTotpMfaProperties;

  IamX509AuthenticationUserDetailService iamX509AuthenticationUserDetailService;
  PreAuthenticatedAuthenticationToken token;

  @BeforeEach
  void setup() {
    iamX509AuthenticationUserDetailService = new IamX509AuthenticationUserDetailService(
        accountRepository, totpMfaRepository, inactiveAccountHandler, iamTotpMfaProperties);
    token = new PreAuthenticatedAuthenticationToken("test-principal", "test-credentials");
  }

  private IamAccount newAccount(String username) {
    IamAccount result = new IamAccount();
    result.setUserInfo(new IamUserInfo());
    result.setPassword("secret");
    result.setUsername(username);
    result.setUuid(UUID.randomUUID().toString());
    return result;
  }

  @Test
  void testIfMfaActiveThenRolePreAuthenticatedIsAdded() {

    IamAccount account = newAccount("test-user");
    when(accountRepository.findByCertificateSubject(anyString())).thenReturn(Optional.of(account));

    IamTotpMfa iamTotpMfa = new IamTotpMfa();
    iamTotpMfa.setActive(true);
    when(totpMfaRepository.findByAccount(account)).thenReturn(Optional.of(iamTotpMfa));

    UserDetails userDetails = iamX509AuthenticationUserDetailService.loadUserDetails(token);

    assertTrue(hasRole(userDetails, "ROLE_PRE_AUTHENTICATED"));
    Map<?, ?> details = (Map<?, ?>) token.getDetails();
    assertTrue(details.containsValue("https://refeds.org/profile/mfa"));
  }

  @Test
  void testIfMfaMandatoryThenRolePreAuthenticatedIsAdded() {

    IamAccount account = newAccount("test-user");
    when(accountRepository.findByCertificateSubject(anyString())).thenReturn(Optional.of(account));

    IamTotpMfa iamTotpMfa = new IamTotpMfa();
    when(totpMfaRepository.findByAccount(account)).thenReturn(Optional.of(iamTotpMfa));
    when(iamTotpMfaProperties.isMultiFactorMandatory()).thenReturn(true);

    UserDetails userDetails = iamX509AuthenticationUserDetailService.loadUserDetails(token);

    assertTrue(hasRole(userDetails, "ROLE_PRE_AUTHENTICATED"));
    Map<?, ?> details = (Map<?, ?>) token.getDetails();
    assertTrue(details.containsValue("https://refeds.org/profile/mfa"));
  }

  private boolean hasRole(UserDetails userDetails, String role) {

    Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
    return authorities.stream().map(GrantedAuthority::getAuthority).anyMatch(role::equals);
  }
}
