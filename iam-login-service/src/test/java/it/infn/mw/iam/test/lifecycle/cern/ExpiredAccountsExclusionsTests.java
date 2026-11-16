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
package it.infn.mw.iam.test.lifecycle.cern;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageImpl;

import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

class ExpiredAccountsExclusionsTests {

  @Test
  void excludedAccountIsNotSuspendedWhileOtherAccountsAreProcessed() {
    assertExcludedAccountIsSkipped(false);
  }

  @Test
  void excludedAccountIsNotRemovedWhileOtherAccountsAreProcessed() {
    assertExcludedAccountIsSkipped(true);
  }

  private void assertExcludedAccountIsSkipped(boolean remove) {
    Clock clock = Clock.fixed(Instant.parse("2026-11-06T12:00:00Z"), ZoneOffset.UTC);
    LifecycleProperties properties = new LifecycleProperties();
    properties.getAccount().getExpiredAccountPolicy().setRemoveExpiredAccounts(remove);
    IamAccountRepository accounts = mock(IamAccountRepository.class);
    IamAccountService service = mock(IamAccountService.class);
    IamAccount failed = expiredAccount("failed");
    IamAccount healthy = expiredAccount("healthy");
    when(accounts.findExpiredAccountsAtTimestamp(any(), any()))
      .thenReturn(new PageImpl<>(List.of(failed, healthy)));
    ExpiredAccountsHandler handler = new ExpiredAccountsHandler(clock, properties, accounts, service);

    handler.handleExpiredAccounts(Set.of(failed.getUuid()));

    verify(service, never()).disableAccount(failed);
    verify(service, never()).deleteAccount(failed);
    if (remove) {
      verify(service).deleteAccount(healthy);
    } else {
      verify(service).disableAccount(healthy);
    }
  }

  private IamAccount expiredAccount(String uuid) {
    IamAccount account = IamAccount.newAccount();
    account.setUuid(uuid);
    account.setUsername(uuid);
    account.setActive(true);
    account.setEndTime(Date.from(Instant.parse("2026-01-01T00:00:00Z")));
    return account;
  }
}
