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
package it.infn.mw.iam.core.web.group;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.core.IamGroupRequestStatus;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamGroupRequest;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRequestRepository;
import it.infn.mw.iam.notification.service.resolver.AddressResolutionService;
import it.infn.mw.iam.notification.service.resolver.AdminNotificationDeliveryStrategy;

@Component
public class GroupRequestReminderTask {

  private static final Logger LOG = LoggerFactory.getLogger(GroupRequestReminderTask.class);

  private static final String GM_AUDIENCE_PREFIX = "gm:";

  @Value("${group-request-reminder.enabled:false}")
  private boolean enabled;

  @Value("${group-request-reminder.threshold-days:5}")
  private int thresholdDays;

  @Value("${group-request-reminder.repeat-interval-days:2}")
  private int repeatIntervalDays;

  @Value("${group-request-reminder.notify-admins:false}")
  private boolean notifyAdmins;

  private final IamGroupRequestRepository groupRequestRepo;
  private final NotificationFactory notificationFactory;
  private final IamEmailNotificationRepository emailNotificationRepo;
  private final AddressResolutionService addressResolutionService;
  private final AdminNotificationDeliveryStrategy adminDeliveryStrategy;

  public GroupRequestReminderTask(
    IamGroupRequestRepository groupRequestRepo,
    NotificationFactory notificationFactory,
    IamEmailNotificationRepository emailNotificationRepo,
    AddressResolutionService addressResolutionService,
    AdminNotificationDeliveryStrategy adminDeliveryStrategy
   ) {
    this.groupRequestRepo = groupRequestRepo;
    this.notificationFactory = notificationFactory;
    this.emailNotificationRepo = emailNotificationRepo;
    this.addressResolutionService = addressResolutionService;
    this.adminDeliveryStrategy = adminDeliveryStrategy;
  }

  public void sendReminders() {

    if (!enabled) {
      return;
    }

    if (thresholdDays < 1 || repeatIntervalDays < 1) {
      LOG.warn(
          "Group request reminder is enabled but misconfigured (threshold-days={}, repeat-interval-days={}); "
              + "both must be >= 1. Skipping.",
          thresholdDays, repeatIntervalDays);
      return;
    }

    Instant now = Instant.now();
    Date cutoffDate = Date.from(now.minus(thresholdDays, ChronoUnit.DAYS));
    Date sinceDate = Date.from(now.minus(repeatIntervalDays, ChronoUnit.DAYS));

    List<IamGroupRequest> pendingRequests =
        groupRequestRepo.findPendingRequestsOlderThan(IamGroupRequestStatus.PENDING, cutoffDate);

    if (pendingRequests.isEmpty()) {
      LOG.debug("No pending group requests older than {} days", thresholdDays);
      return;
    }

    Map<IamGroup, List<IamGroupRequest>> requestsByGroup = pendingRequests.stream()
        .collect(Collectors.groupingBy(IamGroupRequest::getGroup));

    LOG.info("Found {} pending group request(s) across {} group(s) older than {} days",
        pendingRequests.size(), requestsByGroup.size(), thresholdDays);

    for (Map.Entry<IamGroup, List<IamGroupRequest>> entry : requestsByGroup.entrySet()) {
      IamGroup group = entry.getKey();
      List<IamGroupRequest> requests = entry.getValue();

      String subjectPattern = "%for group " + group.getName();

      if (emailNotificationRepo.countGroupMembershipReminders(subjectPattern, sinceDate) > 0) {
        LOG.debug("Reminder already sent within last {} day(s) for group {}", repeatIntervalDays,
            group.getName());
        continue;
      }

      List<String> recipients = resolveRecipients(group);

      if (recipients.isEmpty()) {
        LOG.warn("No recipients found for group {} reminder, skipping", group.getName());
        continue;
      }

      notificationFactory.createGroupMembershipReminderMessage(group, requests, recipients);
      LOG.info("Sent reminder for group {} with {} pending request(s) to {} recipient(s)",
          group.getName(), requests.size(), recipients.size());
    }
  }

  private List<String> resolveRecipients(IamGroup group) {
    List<String> gmAddresses = addressResolutionService
        .resolveAddressesForAudience(GM_AUDIENCE_PREFIX + group.getUuid());

    if (gmAddresses.isEmpty()) {
      LOG.debug("No group managers for the group {}, falling back to admins", group.getName());
      return adminDeliveryStrategy.resolveAdminEmailAddresses();
    }

    if (notifyAdmins) {
      List<String> combinedAddress = new ArrayList<>(gmAddresses);
      adminDeliveryStrategy.resolveAdminEmailAddresses().stream()
          .filter(address -> !combinedAddress.contains(address))
          .forEach(combinedAddress::add);
      return combinedAddress;
    }

    return gmAddresses;
  }
}
