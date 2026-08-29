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
package it.infn.mw.iam.test.core.web.group;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;

import java.lang.reflect.Field;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.IamGroupRequestStatus;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.core.web.group.GroupRequestReminderTask;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamNotificationReceiver;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamGroupRequest;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRequestRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.clock.MutableClock;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class,
    ClockConfig.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
@WithAnonymousUser
@TestPropertySource(properties = {
    "group-request-reminder.enabled=true",
    "group-request-reminder.threshold-days=1",
    "group-request-reminder.repeat-interval-days=1",
    "group-request-reminder.notify-admins=false",
    "notification.disable=false"
})
class GroupRequestReminderTaskTests {

  private static final String GROUP_NAME = "Test-001";

  @Autowired
  private GroupRequestReminderTask reminderTask;

  @Autowired
  private MutableClock clock;

  @Autowired
  private IamGroupRequestRepository groupRequestRepo;

  @Autowired
  private IamGroupRepository groupRepo;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamAuthoritiesRepository authoritiesRepo;

  @Autowired
  private IamEmailNotificationRepository emailRepo;

  @BeforeEach
  void setup() {
    emailRepo.deleteAll();
    groupRequestRepo.deleteAll();
  }

  @Test
  void reminderIsCreatedForOldPendingRequest() {
    IamGroup group = groupRepo.findByName(GROUP_NAME).orElseThrow();
    IamAccount account = accountRepo.findByUsername("test_100").orElseThrow();
    assignGroupManager(account, group);
    savePendingRequest(account, group, 5);

    reminderTask.sendReminders();

    List<IamEmailNotification> reminders = getReminders();
    assertThat(reminders, hasSize(1));
    assertThat(reminders.get(0).getBody(), containsString(GROUP_NAME));
    assertThat(reminders.get(0).getBody(), containsString("test_100"));
    assertThat(reminders.get(0).getBody(), containsString("Dear Group Manager"));
  }

  @Test
  void reminderIsNotDuplicated() {
    IamGroup group = groupRepo.findByName(GROUP_NAME).orElseThrow();
    IamAccount account = accountRepo.findByUsername("test_100").orElseThrow();
    assignGroupManager(account, group);
    savePendingRequest(account, group, 5);

    reminderTask.sendReminders();
    reminderTask.sendReminders();
    reminderTask.sendReminders();

    assertThat(getReminders(), hasSize(1));
  }

  @Test
  void reminderIsSentAgainAfterRepeatInterval() {
    IamGroup group = groupRepo.findByName(GROUP_NAME).orElseThrow();
    IamAccount account = accountRepo.findByUsername("test_100").orElseThrow();
    assignGroupManager(account, group);
    savePendingRequest(account, group, 5);

    reminderTask.sendReminders();
    assertThat(getReminders(), hasSize(1));

    clock.advance(Duration.ofDays(2));
    reminderTask.sendReminders();

    assertThat(getReminders(), hasSize(2));
  }

  @Test
  void noReminderForRecentRequest() {
    IamGroup group = groupRepo.findByName(GROUP_NAME).orElseThrow();
    IamAccount account = accountRepo.findByUsername("test_100").orElseThrow();
    assignGroupManager(account, group);
    savePendingRequest(account, group, 0);

    reminderTask.sendReminders();

    assertThat(getReminders(), hasSize(0));
  }

  @Test
  void noReminderForApprovedRequest() {
    IamGroup group = groupRepo.findByName(GROUP_NAME).orElseThrow();
    IamAccount account = accountRepo.findByUsername("test_100").orElseThrow();
    assignGroupManager(account, group);
    IamGroupRequest request = savePendingRequest(account, group, 5);
    request.setStatus(IamGroupRequestStatus.APPROVED);
    groupRequestRepo.save(request);

    reminderTask.sendReminders();

    assertThat(getReminders(), hasSize(0));
  }

  @Test
  void fallsBackToAdminsWhenNoGroupManager() {
    IamGroup group = groupRepo.findByName(GROUP_NAME).orElseThrow();
    savePendingRequest(accountRepo.findByUsername("test_100").orElseThrow(), group, 5);

    reminderTask.sendReminders();

    assertThat(getReminders(), hasSize(1));
  }

  @Test
  void reminderGroupsMultipleUsersPerGroup() {
    IamGroup group = groupRepo.findByName(GROUP_NAME).orElseThrow();
    IamAccount a1 = accountRepo.findByUsername("test_100").orElseThrow();
    IamAccount a2 = accountRepo.findByUsername("test_101").orElseThrow();
    assignGroupManager(a1, group);
    savePendingRequest(a1, group, 5);
    savePendingRequest(a2, group, 3);

    reminderTask.sendReminders();

    List<IamEmailNotification> reminders = getReminders();
    assertThat(reminders, hasSize(1));
    assertThat(reminders.get(0).getBody(), containsString("test_100"));
    assertThat(reminders.get(0).getBody(), containsString("test_101"));
  }

  @Test
  void doesNothingWhenDisabled() throws Exception {
    setTaskField("enabled", false);
    try {
      IamGroup group = groupRepo.findByName(GROUP_NAME).orElseThrow();
      savePendingRequest(accountRepo.findByUsername("test_100").orElseThrow(), group, 5);

      reminderTask.sendReminders();

      assertThat(getReminders(), hasSize(0));
    } finally {
      setTaskField("enabled", true);
    }
  }

  @Test
  void includesAdminsWhenConfigured() throws Exception {
    setTaskField("notifyAdmins", true);
    try {
      IamGroup group = groupRepo.findByName(GROUP_NAME).orElseThrow();
      IamAccount account = accountRepo.findByUsername("test_100").orElseThrow();
      assignGroupManager(account, group);
      savePendingRequest(account, group, 5);

      reminderTask.sendReminders();

      List<IamEmailNotification> reminders = getReminders();
      assertThat(reminders, hasSize(1));
      assertThat(reminders.get(0).getReceivers().size(), greaterThanOrEqualTo(2));
    } finally {
      setTaskField("notifyAdmins", false);
    }
  }

  @Test
  void skipsWhenMisconfigured() throws Exception {
    setTaskField("thresholdDays", 0);
    try {
      IamGroup group = groupRepo.findByName(GROUP_NAME).orElseThrow();
      IamAccount account = accountRepo.findByUsername("test_100").orElseThrow();
      assignGroupManager(account, group);
      savePendingRequest(account, group, 5);

      reminderTask.sendReminders();

      assertThat(getReminders(), hasSize(0));
    } finally {
      setTaskField("thresholdDays", 1);
    }
  }

  @Test
  void doesNotDuplicateRecipientWhoIsManagerAndAdmin() throws Exception {
    setTaskField("notifyAdmins", true);
    try {
      IamGroup group = groupRepo.findByName(GROUP_NAME).orElseThrow();
      IamAccount account = accountRepo.findByUsername("test_100").orElseThrow();
      assignGroupManager(account, group);
      assignAdmin(account);
      savePendingRequest(account, group, 5);

      reminderTask.sendReminders();

      List<IamEmailNotification> reminders = getReminders();
      assertThat(reminders, hasSize(1));
      List<String> addresses = reminders.get(0).getReceivers().stream()
          .map(IamNotificationReceiver::getEmailAddress).collect(Collectors.toList());
      assertThat(addresses, hasSize(addresses.stream().distinct().collect(Collectors.toList()).size()));
    } finally {
      setTaskField("notifyAdmins", false);
    }
  }

  private List<IamEmailNotification> getReminders() {
    return emailRepo.findByNotificationType(IamNotificationType.GROUP_MEMBERSHIP_REMINDER);
  }

  private void setTaskField(String name, Object value) throws Exception {
    Field field = GroupRequestReminderTask.class.getDeclaredField(name);
    field.setAccessible(true);
    field.set(reminderTask, value);
  }

  private void assignGroupManager(IamAccount account, IamGroup group) {
    String gmAuth = String.format("ROLE_GM:%s", group.getUuid());
    IamAuthority auth = authoritiesRepo.findByAuthority(gmAuth)
        .orElseGet(() -> authoritiesRepo.save(new IamAuthority(gmAuth)));
    account.getAuthorities().add(auth);
    accountRepo.save(account);
  }

  private void assignAdmin(IamAccount account) {
    IamAuthority auth = authoritiesRepo.findByAuthority("ROLE_ADMIN")
        .orElseGet(() -> authoritiesRepo.save(new IamAuthority("ROLE_ADMIN")));
    account.getAuthorities().add(auth);
    accountRepo.save(account);
  }

  private IamGroupRequest savePendingRequest(IamAccount account, IamGroup group, int daysAgo) {
    IamGroupRequest request = new IamGroupRequest();
    request.setUuid(UUID.randomUUID().toString());
    request.setAccount(account);
    request.setGroup(group);
    request.setStatus(IamGroupRequestStatus.PENDING);
    request.setNotes("Test request");
    request.setCreationTime(Date.from(clock.instant().minus(daysAgo, ChronoUnit.DAYS)));
    return groupRequestRepo.save(request);
  }
}
