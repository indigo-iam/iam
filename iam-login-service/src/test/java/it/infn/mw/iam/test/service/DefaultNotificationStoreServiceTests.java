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
package it.infn.mw.iam.test.service;

import static java.util.Collections.emptyList;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import com.google.common.collect.Lists;

import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.notification.service.DefaultNotificationStoreService;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;

@RunWith(MockitoJUnitRunner.class)
public class DefaultNotificationStoreServiceTests {

  public static final String TEST_0_EMAIL = "test0@test.example";
  public static final String TEST_1_EMAIL = "test1@test.example";
  public static final String TEST_EMAIL_SUBJECT = "Subject";
  public static final String TEST_EMAIL_BODY = "Body";

  public static final String IAM_MAIL_FROM = "iam@test.example";
  public static final String IAM_ADMIN_ADDRESS = "admin@test.example";

  public static final Instant NOW = Instant.parse("2021-01-01T00:00:00.00Z");

  @Mock
  private IamEmailNotificationRepository notificationRepo;

  @Mock
  private TimeProvider timeProvider;

  @Mock
  private NotificationProperties properties;

  @InjectMocks
  private DefaultNotificationStoreService service;

  @Captor
  private ArgumentCaptor<Date> dateArgumentCaptor;

  @Captor
  private ArgumentCaptor<IamDeliveryStatus> statusArgumentCaptor;

  @Captor
  private ArgumentCaptor<Iterable<IamEmailNotification>> notificationCaptor;

  @Before
  public void setup() {

    // when(properties.getMailFrom()).thenReturn(IAM_MAIL_FROM);
    // when(properties.getAdminAddress()).thenReturn(IAM_ADMIN_ADDRESS);
    when(properties.getCleanupAge()).thenReturn(1);
  }

  @Test
  public void clearAllNotificationsClearsAllNotifications() {
    service.clearAllNotifications();
    verify(notificationRepo).deleteAll();
  }

  @Test
  public void countPendingNotificationsCallsTheRightRepo() {
    when(notificationRepo.countByDeliveryStatus(IamDeliveryStatus.PENDING)).thenReturn(15);
    assertThat(service.countPendingNotifications(), is(15));

  }

  @Test
  public void clearExpiredNotificationsClearsTheRightNotifications() {

    Date oneDayAfterNow = Date.from(NOW.plus(1L, ChronoUnit.DAYS));
    Date twoDaysAfterNow = Date.from(NOW.plus(2L, ChronoUnit.DAYS));

    IamEmailNotification notification = mock(IamEmailNotification.class);

    when(notificationRepo.findByStatusWithUpdateTime(Mockito.any(), Mockito.any()))
      .thenReturn(Arrays.asList(notification));

    when(timeProvider.currentTimeMillis()).thenReturn(twoDaysAfterNow.getTime());

    service.clearExpiredNotifications();

    verify(notificationRepo).findByStatusWithUpdateTime(statusArgumentCaptor.capture(),
        dateArgumentCaptor.capture());

    assertThat(statusArgumentCaptor.getValue(), is(IamDeliveryStatus.DELIVERED));
    assertThat(dateArgumentCaptor.getValue(), equalTo(oneDayAfterNow));

    verify(notificationRepo).deleteAll(notificationCaptor.capture());

    List<IamEmailNotification> removedNotifications = Lists.newArrayList(notificationCaptor.getValue());
    assertThat(removedNotifications, hasSize(1));
    assertThat(removedNotifications, hasItem(notification));
    
  }
  
  @Test
  public void clearExpiredNotificationsDoesNotClearAnythingWhenThereAreNoExpiredNotifications() {
    
    Date oneDayAfterNow = Date.from(NOW.plus(1L, ChronoUnit.DAYS));
    Date twoDaysAfterNow = Date.from(NOW.plus(2L, ChronoUnit.DAYS));

    when(notificationRepo.findByStatusWithUpdateTime(Mockito.any(), Mockito.any()))
      .thenReturn(emptyList());

    when(timeProvider.currentTimeMillis()).thenReturn(twoDaysAfterNow.getTime());

    service.clearExpiredNotifications();

    verify(notificationRepo).findByStatusWithUpdateTime(statusArgumentCaptor.capture(),
        dateArgumentCaptor.capture());

    assertThat(statusArgumentCaptor.getValue(), is(IamDeliveryStatus.DELIVERED));
    assertThat(dateArgumentCaptor.getValue(), equalTo(oneDayAfterNow));

    verify(notificationRepo, never()).deleteAll(notificationCaptor.capture());
    
    
  }


}
