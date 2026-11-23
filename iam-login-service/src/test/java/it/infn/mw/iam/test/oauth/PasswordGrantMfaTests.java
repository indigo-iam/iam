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

package it.infn.mw.iam.test.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountLoginLockoutRepository;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;

@SuppressWarnings("deprecation")
@SpringBootTest(classes = IamLoginService.class,
    properties = {"iam.login-lockout.enabled=true", "iam.login-lockout.max-failed-attempts=3"})
class PasswordGrantMfaTests implements StructuredScopeTestSupportConstants {

  @Autowired
  @Qualifier("passwordTokenGranter")
  ResourceOwnerPasswordTokenGranter granter;

  @Autowired
  IamAccountService accounts;

  @Autowired
  IamAccountLoginLockoutRepository lockouts;

  @Autowired
  PlatformTransactionManager transactions;

  @SpyBean
  IamTotpMfaService totp;

  @SpyBean
  IamTotpMfaProperties mfa;

  @ParameterizedTest(name = "Password grant rejects pending MFA (global mandatory = {0})")
  @ValueSource(booleans = {false, true})
  void pendingMfaRejectsGrantAndPreservesFailedAttempt(boolean mandatory) {
    String uuid = accounts.findByUsername(TEST_USERNAME).orElseThrow().getUuid();
    doReturn(!mandatory).when(totp).isAuthenticatorAppActive(any(IamAccount.class));
    doReturn(mandatory).when(mfa).isMultiFactorMandatory();

    var tx = new TransactionTemplate(transactions);
    Runnable clear = () -> tx
      .executeWithoutResult(status -> lockouts.findByAccountUuid(uuid).ifPresent(lockouts::delete));
    clear.run();
    try {
      accounts.loginFailedAttemptByUsername(TEST_USERNAME);
      assertEquals(1, lockouts.findByAccountUuid(uuid).orElseThrow().getFailedAttempts());

      var request = new TokenRequest(Map.of("username", TEST_USERNAME, "password", TEST_PASSWORD),
          PASSWORD_CLIENT_ID, Set.of("openid"), "password");
      var error =
          assertThrows(InvalidGrantException.class, () -> granter.grant("password", request));

      assertEquals("invalid_grant", error.getOAuth2ErrorCode());
      assertEquals(1, lockouts.findByAccountUuid(uuid).orElseThrow().getFailedAttempts());
    } finally {
      clear.run();
    }
  }
}
