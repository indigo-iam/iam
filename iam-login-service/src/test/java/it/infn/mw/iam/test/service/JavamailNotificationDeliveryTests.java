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

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItemInArray;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.notification.service.JavaMailNotificationDelivery;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamNotificationReceiver;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;

@RunWith(MockitoJUnitRunner.class)
public class JavamailNotificationDeliveryTests {

  public static final String TEST_0_EMAIL = "test0@test.example";
  public static final String TEST_1_EMAIL = "test1@test.example";
  public static final String TEST_EMAIL_SUBJECT = "Subject";
  public static final String TEST_EMAIL_BODY = "Body";

  public static final String IAM_MAIL_FROM = "iam@test.example";
  public static final String IAM_ADMIN_ADDRESS = "admin@test.example";

  @Mock
  JavaMailSender mailSender;

  @Mock
  IamEmailNotificationRepository notificationRepo;

  @Mock
  TimeProvider timeProvider;

  @Mock
  NotificationProperties properties;

  @InjectMocks
  private JavaMailNotificationDelivery delivery;

  @Captor
  ArgumentCaptor<IamDeliveryStatus> statusArgumentCaptor;

  @Captor
  ArgumentCaptor<SimpleMailMessage> messageArgumentCaptor;
  
  @Before
  public void setup() {

    when(properties.getMailFrom()).thenReturn(IAM_MAIL_FROM);
    // when(properties.getAdminAddress()).thenReturn(IAM_ADMIN_ADDRESS);
  }


  @Test
  public void testNoMessageDelivery() {
    when(notificationRepo.findByDeliveryStatus(IamDeliveryStatus.PENDING)).thenReturn(emptyList());

    delivery.sendPendingNotifications();
    verifyNoInteractions(mailSender);
  }

  @Test
  public void testMessageIsDelivered() {

    
    IamEmailNotification notification = mock(IamEmailNotification.class);
    IamNotificationReceiver receiver = mock(IamNotificationReceiver.class);

    // when(receiver.getIamEmailNotification()).thenReturn(notification);
    when(receiver.getEmailAddress()).thenReturn(TEST_0_EMAIL);

    when(notification.getBody()).thenReturn("Body");
    when(notification.getSubject()).thenReturn("Subject");
    // when(notification.getDeliveryStatus()).thenReturn(IamDeliveryStatus.PENDING);


    when(notification.getReceivers()).thenReturn(asList(receiver));

    when(notificationRepo.findByDeliveryStatus(IamDeliveryStatus.PENDING))
      .thenReturn(asList(notification));

    delivery.sendPendingNotifications();

    verify(notification).setDeliveryStatus(statusArgumentCaptor.capture());
    verify(mailSender).send(messageArgumentCaptor.capture());

    assertThat(statusArgumentCaptor.getValue(), is(IamDeliveryStatus.DELIVERED));
    assertThat(messageArgumentCaptor.getValue().getFrom(), equalTo(IAM_MAIL_FROM));
    assertThat(messageArgumentCaptor.getValue().getSubject(), equalTo(TEST_EMAIL_SUBJECT));
    assertThat(messageArgumentCaptor.getValue().getText(), equalTo(TEST_EMAIL_BODY));
    assertThat(messageArgumentCaptor.getValue().getTo(), arrayWithSize(1));
    assertThat(messageArgumentCaptor.getValue().getTo(), hasItemInArray(TEST_0_EMAIL));

  }

  @Test
  public void testDeliveryErrorIsPropagated() {
    IamEmailNotification notification = Mockito.mock(IamEmailNotification.class);
    IamNotificationReceiver receiver = Mockito.mock(IamNotificationReceiver.class);

    // when(receiver.getIamEmailNotification()).thenReturn(notification);
    // when(receiver.getEmailAddress()).thenReturn(TEST_0_EMAIL);

    when(notification.getBody()).thenReturn("Body");
    when(notification.getSubject()).thenReturn("Subject");
    // when(notification.getDeliveryStatus()).thenReturn(IamDeliveryStatus.PENDING);
    // when(notification.getCreationTime()).thenReturn(currentTime);
    // when(notification.getUuid()).thenReturn(randomUuid);

    doThrow(new MailSendException("Error sending email")).when(mailSender)
      .send(Mockito.any(SimpleMailMessage.class));

    when(notification.getReceivers()).thenReturn(asList(receiver));

    when(notificationRepo.findByDeliveryStatus(IamDeliveryStatus.PENDING))
      .thenReturn(asList(notification));

    delivery.sendPendingNotifications();
    verify(notification).setDeliveryStatus(statusArgumentCaptor.capture());
    verify(mailSender).send(messageArgumentCaptor.capture());
    
    assertThat(statusArgumentCaptor.getValue(), is(IamDeliveryStatus.DELIVERY_ERROR));
  }

}
