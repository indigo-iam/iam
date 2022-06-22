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
package it.infn.mw.iam.authn.saml;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;

public class CleanInactiveProvisionedAccounts implements Runnable {

  public static final Logger LOG = LoggerFactory.getLogger(CleanInactiveProvisionedAccounts.class);

  final TimeProvider timeProvider;
  final IamAccountService accountService;
  final int inactiveUserLifetimeInDays;

  public CleanInactiveProvisionedAccounts(TimeProvider timeProvider,
      IamAccountService accountService, int inactiveUserLifetimeInDays) {
    checkNotNull(timeProvider, "null timeProvider");
    checkNotNull(accountService, "null accountService");
    checkArgument(inactiveUserLifetimeInDays > 0, "inactiveUserLifetimeInDays must be > 0");
    this.timeProvider = timeProvider;
    this.accountService = accountService;
    this.inactiveUserLifetimeInDays = inactiveUserLifetimeInDays;
  }

  private Date computeProvisionedUsersExpirationTimestamp() {
    LocalDateTime ldt = LocalDateTime
      .ofInstant(Instant.ofEpochMilli(timeProvider.currentTimeMillis()), ZoneId.systemDefault());

    return Date
      .from(ldt.minusDays(inactiveUserLifetimeInDays).atZone(ZoneId.systemDefault()).toInstant());
  }

  @Override
  public void run() {
    Date expirationTimestamp = computeProvisionedUsersExpirationTimestamp();

    LOG.info("Attempting removal of provisioned accounts inactive since {}", expirationTimestamp);

    List<IamAccount> removedAccounts =
        accountService.deleteInactiveProvisionedUsersSinceTime(expirationTimestamp);

    if (removedAccounts.isEmpty()) {
      LOG.info("No accounts removed");
    } else {
      removedAccounts.forEach(a -> LOG.info("Removed inactive provisioned account: {}", a));
    }
  }

}
