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

import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.AccountLifecycleStatus.PENDING_REMOVAL;
import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.AccountLifecycleStatus.SUSPENDED;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_CERN_PREFIX;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.api.registration.cern.CernHrDbApiError;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.config.cern.CernProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

@Component
@Profile("cern")
public class CernHrLifecycleHandler implements Runnable {

  public static final String INVALID_ACCOUNT_MESSAGE =
      "Account has not the mandatory CERN person id label";

  public static final String IGNORE_MESSAGE = "Skipping account as requested by the 'ignore' label";
  public static final String NO_PERSON_FOUND_MESSAGE = "No person id %s found on HR DB";
  public static final String NO_PARTICIPATION_MESSAGE =
      "Account end-time not updated: no participation to %s found";
  public static final String SYNCHRONIZED_MESSAGE =
      "Account's membership to the experiment synchronized";

  public static final String HR_DB_API_ERROR = "Account not updated: HR DB error";

  public static final int DEFAULT_PAGE_SIZE = 50;

  protected static final List<String> SUSPENDED_STATUSES =
      Lists.newArrayList(SUSPENDED.name(), PENDING_REMOVAL.name());

  public static final Logger LOG = LoggerFactory.getLogger(CernHrLifecycleHandler.class);

  private final CernProperties cernProperties;
  private final IamAccountRepository accountRepo;
  private final CernHrDBApiService hrDb;
  private final CernHrLifecycleAccountProcessor accountProcessor;

  public CernHrLifecycleHandler(CernProperties cernProperties, IamAccountRepository accountRepo,
      CernHrDBApiService hrDb, CernHrLifecycleAccountProcessor accountProcessor) {
    this.cernProperties = cernProperties;
    this.accountRepo = accountRepo;
    this.hrDb = hrDb;
    this.accountProcessor = accountProcessor;
  }

  public void handleAccount(String cernPersonId, String experiment, IamAccount account) {
    synchronizeAccount(cernPersonId, experiment, account);
  }

  private enum SyncOutcome {
    SYNCHRONIZED, IGNORED, FAILED
  }

  private SyncOutcome synchronizeAccount(String cernPersonId, String experiment,
      IamAccount account) {
    if (accountProcessor.skipIfIgnored(account.getUuid())) {
      return SyncOutcome.IGNORED;
    }
    // External I/O must not hold a database row lock.
    Optional<VOPersonDTO> person;
    try {
      person = hrDb.getHrDbPersonRecord(cernPersonId);
    } catch (CernHrDbApiError e) {
      LOG.error("Error contacting HR DB api: {}", e.getMessage(), e);
      accountProcessor.processApiError(account.getUuid());
      return SyncOutcome.FAILED;
    }
    accountProcessor.process(account.getUuid(), cernPersonId, experiment, person);
    return SyncOutcome.SYNCHRONIZED;
  }

  private String getCernPersonId(IamAccount account) {
    Optional<IamLabel> label =
        account.getLabelByPrefixAndName(LABEL_CERN_PREFIX, cernProperties.getPersonIdClaim());
    Assert.isTrue(label.isPresent(), INVALID_ACCOUNT_MESSAGE);
    return label.get().getValue();
  }

  @Override
  @SchedulerLock(name = "accountLifecycle",
      lockAtMostFor = "${lifecycle.account.lock-at-most-for:PT2H}")
  public void run() {
    synchronizeAccounts();
  }

  /** Returns accounts whose synchronization failed during this cycle. */
  public Set<String> synchronizeAccounts() {
    Set<String> failedAccounts = new HashSet<>();
    long startedAt = System.nanoTime();
    long synchronizedCount = 0;
    long ignoredCount = 0;
    long processedCount = 0;

    LOG.info("CERN HR lifecycle handler ... [START]");

    Pageable pageRequest =
        PageRequest.of(0, cernProperties.getTask().getPageSize(), Sort.by("id").ascending());

    while (true) {
      Page<IamAccount> accountsPage = accountRepo.findByLabelPrefixAndName(LABEL_CERN_PREFIX,
          cernProperties.getPersonIdClaim(), pageRequest);

      LOG.debug("accountsPage: {}", accountsPage);

      if (accountsPage.hasContent()) {
        for (IamAccount a : accountsPage.getContent()) {
          processedCount++;
          try {
            SyncOutcome outcome =
                synchronizeAccount(getCernPersonId(a), cernProperties.getExperimentName(), a);
            switch (outcome) {
              case SYNCHRONIZED:
                synchronizedCount++;
                break;
              case IGNORED:
                ignoredCount++;
                break;
              case FAILED:
                failedAccounts.add(a.getUuid());
                break;
              default:
                throw new IllegalStateException("Unexpected HR sync outcome: " + outcome);
            }
          } catch (RuntimeException e) {
            failedAccounts.add(a.getUuid());
            LOG.error("Error during CERN HR lifecycle handler on account {}", a.getUuid(), e);
          }
        }
      }

      if (!accountsPage.hasNext()) {
        break;
      }

      pageRequest = accountsPage.nextPageable();
    }

    LOG.info("CERN HR lifecycle handler ... [END] processed={}, synchronized={}, ignored={}, "
        + "failed={}, durationMs={}", processedCount, synchronizedCount, ignoredCount,
        failedAccounts.size(), TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt));
    return failedAccounts;
  }

}
