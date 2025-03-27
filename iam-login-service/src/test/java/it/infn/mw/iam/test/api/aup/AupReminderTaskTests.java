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
package it.infn.mw.iam.test.api.aup;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.web.aup.AupReminderTask;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.service.aup.DefaultAupSignatureCheckService;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.notification.NotificationTestConfig;
import it.infn.mw.iam.test.util.MockTimeProvider;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.notification.MockNotificationDelivery;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class,
    NotificationTestConfig.class}, webEnvironment = WebEnvironment.MOCK)
@WithAnonymousUser
@TestPropertySource(properties = {"notification.disable=false"})
public class AupReminderTaskTests extends AupTestSupport {

  @Autowired
  private DefaultAupSignatureCheckService service;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamAupSignatureRepository signatureRepo;

  @Autowired
  private IamEmailNotificationRepository notificationRepo;

  @Autowired
  private AupReminderTask aupReminderTask;

  @Autowired
  private MockNotificationDelivery notificationDelivery;

  @Autowired
  private IamAupRepository aupRepo;

  @Autowired
  private MockTimeProvider mockTimeProvider;

  @After
  public void tearDown() {
    notificationDelivery.clearDeliveredNotifications();
    aupRepo.deleteAll();
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupReminderEmailWorks() {
    IamAup aup = buildDefaultAup();
    aup.setSignatureValidityInDays(30L);
    aupRepo.save(aup);

    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());
    LocalDate today = LocalDate.now();
    LocalDate tomorrow = today.plusDays(1);
    Date tomorrowDate = Date.from(tomorrow.atStartOfDay(ZoneId.systemDefault()).toInstant());

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    mockTimeProvider.setTime(now.getTime() + TimeUnit.MINUTES.toMillis(5));

    assertThat(service.needsAupSignature(testAccount), is(true));

    signatureRepo.createSignatureForAccount(aup, testAccount,
        new Date(mockTimeProvider.currentTimeMillis()));

    assertThat(service.needsAupSignature(testAccount), is(false));

    mockTimeProvider.setTime(now.getTime() + TimeUnit.MINUTES.toMillis(10));

    assertThat(notificationRepo.countAupRemindersPerAccount(testAccount.getUserInfo().getEmail(),
        tomorrowDate), equalTo(0));

    aupReminderTask.sendAupReminders();
    notificationDelivery.sendPendingNotifications();
    assertThat(notificationRepo.countAupRemindersPerAccount(testAccount.getUserInfo().getEmail(),
        tomorrowDate), equalTo(1));

  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupExpirationEmailWorks() {
    IamAup aup = buildDefaultAup();
    aup.setSignatureValidityInDays(2L);

    LocalDate today = LocalDate.now();
    LocalDate twoDaysAgo = today.minusDays(2);

    Date date = Date.from(twoDaysAgo.atStartOfDay(ZoneId.systemDefault()).toInstant());
    aup.setCreationTime(date);
    aup.setLastUpdateTime(date);

    aupRepo.save(aup);

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    signatureRepo.createSignatureForAccount(aup, testAccount, date);

    assertThat(
        notificationRepo.countAupExpirationMessPerAccount(testAccount.getUserInfo().getEmail()),
        equalTo(0));

    aupReminderTask.sendAupReminders();
    notificationDelivery.sendPendingNotifications();
    assertThat(
        notificationRepo.countAupExpirationMessPerAccount(testAccount.getUserInfo().getEmail()),
        equalTo(1));

    aupReminderTask.sendAupReminders();
    notificationDelivery.sendPendingNotifications();
    assertThat(
        notificationRepo.countAupExpirationMessPerAccount(testAccount.getUserInfo().getEmail()),
        equalTo(1));

  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupExpirationEmailNotSentIfUserIsDisabled() {
    IamAup aup = buildDefaultAup();
    aup.setSignatureValidityInDays(2L);

    LocalDate today = LocalDate.now();
    LocalDate twoDaysAgo = today.minusDays(2);

    Date date = Date.from(twoDaysAgo.atStartOfDay(ZoneId.systemDefault()).toInstant());
    aup.setCreationTime(date);
    aup.setLastUpdateTime(date);

    aupRepo.save(aup);

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    signatureRepo.createSignatureForAccount(aup, testAccount, date);

    assertThat(
        notificationRepo.countAupExpirationMessPerAccount(testAccount.getUserInfo().getEmail()),
        equalTo(0));

    testAccount.setActive(false);
    accountRepo.save(testAccount);

    aupReminderTask.sendAupReminders();
    notificationDelivery.sendPendingNotifications();
    assertThat(
        notificationRepo.countAupExpirationMessPerAccount(testAccount.getUserInfo().getEmail()),
        equalTo(0));

  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupExpirationEmailNotSentIfAupSignatureValidityIsZero() {
    IamAup aup = buildDefaultAup();
    aup.setSignatureValidityInDays(0L);

    LocalDate today = LocalDate.now();
    Date date = Date.from(today.atStartOfDay(ZoneId.systemDefault()).toInstant());

    aup.setCreationTime(date);
    aup.setLastUpdateTime(date);

    aupRepo.save(aup);

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    signatureRepo.createSignatureForAccount(aup, testAccount, date);

    aupReminderTask.sendAupReminders();
    notificationDelivery.sendPendingNotifications();
    assertThat(
        notificationRepo.countAupExpirationMessPerAccount(testAccount.getUserInfo().getEmail()),
        equalTo(0));

  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupExpirationEmailNotSentForServiceAccount() {
    IamAup aup = buildDefaultAup();
    aup.setSignatureValidityInDays(2L);

    LocalDate today = LocalDate.now();
    LocalDate twoDaysAgo = today.minusDays(2);

    Date date = Date.from(twoDaysAgo.atStartOfDay(ZoneId.systemDefault()).toInstant());
    aup.setCreationTime(date);
    aup.setLastUpdateTime(date);
    aupRepo.save(aup);

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    signatureRepo.createSignatureForAccount(aup, testAccount, date);

    testAccount.setServiceAccount(true);  
    accountRepo.save(testAccount);

    assertThat(
        notificationRepo.countAupExpirationMessPerAccount(testAccount.getUserInfo().getEmail()),
        equalTo(0));

    aupReminderTask.sendAupReminders();
    notificationDelivery.sendPendingNotifications();
    assertThat(
        notificationRepo.countAupExpirationMessPerAccount(testAccount.getUserInfo().getEmail()),
        equalTo(0));

  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupReminderEmailNotSentForServiceAccount() {
    IamAup aup = buildDefaultAup();
    aup.setSignatureValidityInDays(30L);
    aupRepo.save(aup);

    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());
    LocalDate today = LocalDate.now();
    LocalDate tomorrow = today.plusDays(1);
    Date tomorrowDate = Date.from(tomorrow.atStartOfDay(ZoneId.systemDefault()).toInstant());

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    mockTimeProvider.setTime(now.getTime() + TimeUnit.MINUTES.toMillis(5));

    assertThat(service.needsAupSignature(testAccount), is(true));

    signatureRepo.createSignatureForAccount(aup, testAccount,
        new Date(mockTimeProvider.currentTimeMillis()));

    assertThat(service.needsAupSignature(testAccount), is(false));

    testAccount.setServiceAccount(true);  
    accountRepo.save(testAccount);

    mockTimeProvider.setTime(now.getTime() + TimeUnit.MINUTES.toMillis(10));

    assertThat(notificationRepo.countAupRemindersPerAccount(testAccount.getUserInfo().getEmail(),
        tomorrowDate), equalTo(0));

    aupReminderTask.sendAupReminders();
    notificationDelivery.sendPendingNotifications();
    assertThat(notificationRepo.countAupRemindersPerAccount(testAccount.getUserInfo().getEmail(),
        tomorrowDate), equalTo(0));

  }
}
