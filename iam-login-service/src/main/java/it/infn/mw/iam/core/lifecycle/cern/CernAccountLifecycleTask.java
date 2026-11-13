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
package it.infn.mw.iam.core.lifecycle.cern;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.config.cern.CernProperties;
import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

@Component
@Profile("cern")
public class CernAccountLifecycleTask {

  private static final Logger LOG = LoggerFactory.getLogger(CernAccountLifecycleTask.class);

  private final CernProperties cernProperties;
  private final LifecycleProperties lifecycleProperties;
  private final CernHrLifecycleHandler hrHandler;
  private final ExpiredAccountsHandler expiredAccountsHandler;

  public CernAccountLifecycleTask(CernProperties cernProperties,
      LifecycleProperties lifecycleProperties, CernHrLifecycleHandler hrHandler,
      ExpiredAccountsHandler expiredAccountsHandler) {
    this.cernProperties = cernProperties;
    this.lifecycleProperties = lifecycleProperties;
    this.hrHandler = hrHandler;
    this.expiredAccountsHandler = expiredAccountsHandler;
  }

  public boolean isEnabled() {
    return cernProperties.getTask().isEnabled();
  }

  @SchedulerLock(name = "accountLifecycle",
      lockAtMostFor = "${lifecycle.account.lock-at-most-for:PT2H}")
  public void run() {
    if (!isEnabled()) {
      return;
    }
    Set<String> failedAccounts = hrHandler.synchronizeAccounts();
    if (lifecycleProperties.getAccount().getExpiredAccountsTask().isEnabled()) {
      LOG.info("Processing expired accounts after HR sync, excluding {} failed accounts",
          failedAccounts.size());
      expiredAccountsHandler.handleExpiredAccounts(failedAccounts);
    }
  }
}
