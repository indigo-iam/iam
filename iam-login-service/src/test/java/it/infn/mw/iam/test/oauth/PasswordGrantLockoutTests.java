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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.core.oauth.granters.IamResourceOwnerPasswordTokenGranter;
import it.infn.mw.iam.persistence.repository.IamAccountLoginLockoutRepository;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;
import it.infn.mw.iam.test.config.ClockConfig;

@SuppressWarnings("deprecation")
@SpringBootTest(classes = {IamLoginService.class, ClockConfig.class},
    webEnvironment = WebEnvironment.NONE,
    properties = {"iam.login-lockout.enabled=true", "iam.login-lockout.max-failed-attempts=3",
        "iam.login-lockout.observation-window=15m", "iam.login-lockout.lock-duration=30m"})
class PasswordGrantLockoutTests {

  @Autowired
  @Qualifier("authenticationManager")
  AuthenticationManager manager;

  @Autowired
  IamAccountRepository accounts;

  @Autowired
  IamAccountLoginLockoutRepository lockouts;

  @Autowired
  PlatformTransactionManager transactions;

  @Autowired
  Clock clock;

  @Test
  void failedPasswordGrantsSuspendAccountAndPreventTokenIssuance() {
    var client = new BaseClientDetails("unit-client", null, "openid", "password", null);
    var clients = mock(ClientDetailsService.class);
    when(clients.loadClientByClientId(client.getClientId())).thenReturn(client);
    var tokens = mock(AuthorizationServerTokenServices.class);
    OAuth2RequestFactory requests = new DefaultOAuth2RequestFactory(clients);
    var granter = new IamResourceOwnerPasswordTokenGranter(manager, tokens, clients, requests,
        mock(AUPSignatureCheckService.class), mock(AccountUtils.class));

    var uuid = accounts.findByUsername("test").orElseThrow().getUuid();
    var tx = new TransactionTemplate(transactions);
    Runnable clear = () -> tx
      .executeWithoutResult(status -> lockouts.findByAccountUuid(uuid).ifPresent(lockouts::delete));
    clear.run();
    try {
      for (int attempt = 0; attempt < 3; attempt++) {
        assertThrows(InvalidGrantException.class,
            () -> granter.grant("password", request("incorrect")));
      }
      boolean suspended = lockouts.findByAccountUuid(uuid)
        .map(row -> row.isSuspended(clock.instant()))
        .orElse(false);

      assertTrue(suspended, "Three rejected grants must suspend the test account");
      assertEquals("invalid_grant", assertThrows(InvalidGrantException.class,
          () -> granter.grant("password", request("password"))).getOAuth2ErrorCode());
      verify(tokens, never()).createAccessToken(any());
    } finally {
      clear.run();
    }
  }

  private TokenRequest request(String password) {
    return new TokenRequest(Map.of("username", "test", "password", password), "unit-client",
        Set.of("openid"), "password");
  }
}
