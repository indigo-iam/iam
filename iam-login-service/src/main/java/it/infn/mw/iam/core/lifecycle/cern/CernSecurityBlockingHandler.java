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

import static java.lang.String.format;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.registration.cern.CernSecurityBlockingApiService;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_CERN_PREFIX;
import it.infn.mw.iam.api.registration.cern.CernSecurityBlockingError;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.config.cern.CernProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.model.IamLabel;

@Component
@Profile("cern")
public class CernSecurityBlockingHandler implements Runnable, SchedulingConfigurer {

    public static final Logger LOG = LoggerFactory.getLogger(CernSecurityBlockingHandler.class);
    private final CernProperties cernProperties;
    private final IamAccountRepository accountRepo;
    private final IamAccountService accountService;
    private final CernSecurityBlockingApiService cernSecurityBlockingApiService;
    public static final String BLOCKED_MESSAGE = "Account is blocked at CERN";
    public static final String SYNCHRONIZED_MESSAGE ="Account's membership to the experiment synchronized";

    public CernSecurityBlockingHandler(CernProperties cernProperties, IamAccountRepository accountRepo,
        IamAccountService accountService, CernSecurityBlockingApiService  cernSecurityBlockingApiService) {
        this.cernProperties = cernProperties;
        this.accountRepo = accountRepo;
        this.accountService = accountService;
        this.cernSecurityBlockingApiService = cernSecurityBlockingApiService;
    }

    @Override
    public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {

    if (!cernProperties.getBlocking().isEnabled()) {
        LOG.info("CERN Security Blocking Handler is DISABLED");
    } else {
        final String cronSchedule = cernProperties.getBlocking().getCronSchedule();
        LOG.info("Scheduling CERN Security Blocking Handler with schedule: {}", cronSchedule);
        taskRegistrar.addCronTask(this, cronSchedule);
        }
    }

    public void handleAccount(IamAccount a) {
        
        String username = a.getUsername();
        LOG.debug("Handling IAM account (username: {} , uuid: {})", username, a.getUuid());
        
        Optional<VOPersonDTO> voPerson = Optional.empty();
        try {

            voPerson = cernSecurityBlockingApiService.getSecurityBlockingRecord(username);
            LOG.debug("Received security blocking information for account with username: {} , blocking status: {}, active: {}", username, voPerson.isPresent() ? voPerson.get().getBlocked() : "No record found", a.isActive());
        } catch (CernSecurityBlockingError e) {
            LOG.error("Error contacting CERN Authorization api: {}", e.getMessage(), e);
            return;
        }

        if (a.isActive()) {
            if (voPerson.isPresent() && voPerson.get().getBlocked()) {
                LOG.info("Account with username: {} is active but blocked in CERN, disabling account", username);
                disableAccount(a);
            } else {
                LOG.debug("Account with username: {} is active and not blocked in CERN, no action needed", username);
            }
        } else {
            if (voPerson.isPresent() && voPerson.get().getBlocked()) {
                LOG.debug("Account with username: {} is already disabled and blocked in CERN, no action needed", username);
            } else {
                LOG.info("Account with username: {} is disabled but not blocked in CERN, setting status label to ACTIVE", username);
                restoreAccount(a);
                setCernStatusLabel(a, CernStatus.VO_MEMBER, format(SYNCHRONIZED_MESSAGE));
            }
        }
    }

    @Override
    public void run() {

    LOG.info("CERN Security Blocking Handler ... [START]");

    Pageable pageRequest = PageRequest.of(0, cernProperties.getBlocking().getPageSize());

    while (true) {
        Page<IamAccount> accountsPage = accountRepo.findByLabelPrefixAndName(LABEL_CERN_PREFIX,cernProperties.getPersonIdClaim(), pageRequest);
        
        if (accountsPage.hasContent()) {
            for (IamAccount a : accountsPage.getContent()) {
                try {
                    handleAccount(a);
                } catch (RuntimeException e) {
                    LOG.error("Error during CERN Security Blocking Handler on account {}: {}", a, e.getMessage());
                }
            }
        }

        if (!accountsPage.hasNext()) {
            break;
        }
            pageRequest = accountsPage.nextPageable();
        }

        LOG.info("CERN Security Blocking Handler ... [END]");
    }

    private void disableAccount(IamAccount a) {
        accountService.disableAccount(a);
        setCernStatusLabel(a, CernStatus.BLOCKED, BLOCKED_MESSAGE);
    }

    private void setCernStatusLabel(IamAccount a, CernStatus status, String message) {
        IamLabel statusLabel = CernHrLifecycleUtils.buildCernStatusLabel(status);
        IamLabel messageLabel = CernHrLifecycleUtils.buildCernMessageLabel(message);
        accountService.addLabel(a, statusLabel);
        accountService.addLabel(a, messageLabel);
    }
    private void restoreAccount(IamAccount a) {
        accountService.restoreAccount(a);
  }

}