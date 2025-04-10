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
package it.infn.mw.iam.config;

import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.authn.CleanInactiveProvisionedAccounts;
import it.infn.mw.iam.core.time.SystemTimeProvider;
import it.infn.mw.iam.core.user.IamAccountService;

@Component
public class JitCleanupScheduler {
  private static final Logger LOG = LoggerFactory.getLogger(JitCleanupScheduler.class);

  public void scheduleCleanupTask(ScheduledTaskRegistrar taskRegistrar,
      JitProvisioningProperties jitProperties, IamAccountService accountService,
      String protocolName) {
    if (!Boolean.TRUE.equals(jitProperties.getEnabled())) {
      LOG.info("Just-in-time account provisioning for {} is DISABLED.", protocolName);
      return;
    }

    if (!Boolean.TRUE.equals(jitProperties.getCleanupTaskEnabled())) {
      LOG.info("Cleanup for {} JIT account provisioning is DISABLED.", protocolName);
      return;
    }

    LOG.info(
        "Scheduling Just-in-time provisioned account cleanup task for {} to run every {} seconds. "
            + "Accounts inactive for {} days will be deleted",
        protocolName, jitProperties.getCleanupTaskPeriodSec(),
        jitProperties.getInactiveAccountLifetimeDays());

    taskRegistrar.addFixedRateTask(
        new CleanInactiveProvisionedAccounts(new SystemTimeProvider(), accountService,
            jitProperties.getInactiveAccountLifetimeDays()),
        TimeUnit.SECONDS.toMillis(jitProperties.getCleanupTaskPeriodSec()));
  }
}
