/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.core.lifecycle;

import static it.infn.mw.iam.core.IamNotificationType.ACCOUNT_PENDING_SUSPENSION;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;

@Component
public class PendingSuspensionNotificationTask implements Runnable {

  public static final Logger LOG = LoggerFactory.getLogger(PendingSuspensionNotificationTask.class);

  private final LifecycleProperties properties;
  private final IamAccountRepository accountRepo;
  private final IamEmailNotificationRepository notificationRepo;
  private final NotificationFactory notificationFactory;

  public PendingSuspensionNotificationTask(
      LifecycleProperties properties,
      IamAccountRepository accountRepo,
      IamEmailNotificationRepository notificationRepo,
      NotificationFactory notificationFactory) {
    this.properties = properties;
    this.accountRepo = accountRepo;
    this.notificationRepo = notificationRepo;
    this.notificationFactory = notificationFactory;
  }

  public void createPendingSuspensionDigest() {

    List<IamAccount> accountsPendingSuspension = new ArrayList<>();
    Pageable pageRequest =
        PageRequest.of(0, ExpiredAccountsHandler.PAGE_SIZE, Sort.by(Direction.ASC, "endTime"));

    while (true) {
      Page<IamAccount> expiredAccountsPage =
          accountRepo.findByLabelNameAndValue(
              ExpiredAccountsHandler.LIFECYCLE_STATUS_LABEL,
              ExpiredAccountsHandler.AccountLifecycleStatus.PENDING_SUSPENSION.name(),
              pageRequest);

      if (expiredAccountsPage.hasContent()) {
        accountsPendingSuspension.addAll(expiredAccountsPage.getContent());
      }

      if (!expiredAccountsPage.hasNext()) {
        break;
      }

      pageRequest = expiredAccountsPage.nextPageable();
    }

    if (accountsPendingSuspension.isEmpty()) {
      LOG.debug("No accounts pending suspension found");
      return;
    }

    // Skip all older pending digests of this type, keep only the latest
    List<IamEmailNotification> oldPendingDigests =
        notificationRepo.findByNotificationType(ACCOUNT_PENDING_SUSPENSION);
    for (IamEmailNotification oldDigest : oldPendingDigests) {
      if (oldDigest.getDeliveryStatus() == IamDeliveryStatus.PENDING) {
        oldDigest.setDeliveryStatus(IamDeliveryStatus.SKIPPED);
        notificationRepo.save(oldDigest);
        LOG.debug("Skipped pending digest id={}", oldDigest.getId());
      }
    }

    LOG.info(
        "Creating pending suspension digest for {} accounts", accountsPendingSuspension.size());
    notificationFactory.createPendingSuspensionAccountsMessage(
        accountsPendingSuspension,
        properties.getAccount().getExpiredAccountPolicy().getSuspensionGracePeriodDays());
  }

  @Override
  public void run() {
    createPendingSuspensionDigest();
  }
}
