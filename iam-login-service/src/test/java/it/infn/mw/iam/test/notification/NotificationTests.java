package it.infn.mw.iam.test.notification;

import static it.infn.mw.iam.test.RegistrationUtils.confirmRegistrationRequest;
import static it.infn.mw.iam.test.RegistrationUtils.createRegistrationRequest;
import static it.infn.mw.iam.test.RegistrationUtils.deleteUser;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.mail.MessagingException;

import org.apache.commons.lang.time.DateUtils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.subethamail.wiser.Wiser;
import org.subethamail.wiser.WiserMessage;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.notification.MockTimeProvider;
import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.notification.NotificationService;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.RegistrationUtils;
import it.infn.mw.iam.test.TestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class NotificationTests {

  @Autowired
  @Qualifier("defaultNotificationService")
  private NotificationService notificationService;

  @Autowired
  private NotificationProperties properties;

  @Value("${spring.mail.host}")
  private String mailHost;

  @Value("${spring.mail.port}")
  private Integer mailPort;

  @Autowired
  private IamEmailNotificationRepository notificationRepository;

  @Autowired
  private MockTimeProvider timeProvider;

  @Autowired
  private PersistentUUIDTokenGenerator generator;

  private Wiser wiser;


  @BeforeClass
  public static void init() {

    TestUtils.initRestAssured();
  }

  @Before
  public void setUp() {
    wiser = new Wiser();
    wiser.setHostname(mailHost);
    wiser.setPort(mailPort);
    wiser.start();
  }

  @After
  public void tearDown() throws InterruptedException {
    wiser.stop();
    Thread.sleep(1000L);
  }

  @Test
  public void testSendEmails() throws MessagingException {

    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);
    notificationService.sendPendingNotification();

    Assert.assertTrue("element count", wiser.getMessages().size() == 1);
    WiserMessage message = wiser.getMessages().get(0);

    Assert.assertTrue("sender", properties.getMailFrom().equals(message.getEnvelopeSender()));
    Assert.assertTrue("receiver", message.getEnvelopeReceiver().startsWith(username));
    Assert.assertTrue("subject",
        properties.getSubject().get("confirmation").equals(message.getMimeMessage().getSubject()));

    Iterable<IamEmailNotification> queue = notificationRepository.findAll();
    for (IamEmailNotification elem : queue) {
      Assert.assertTrue("status", IamDeliveryStatus.DELIVERED.equals(elem.getDeliveryStatus()));
    }

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testDisableNotificationOption() {
    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);

    properties.setDisable(true);
    notificationService.sendPendingNotification();

    Assert.assertTrue("element count", wiser.getMessages().size() == 0);

    Iterable<IamEmailNotification> queue = notificationRepository.findAll();
    for (IamEmailNotification elem : queue) {
      Assert.assertTrue("status", IamDeliveryStatus.DELIVERED.equals(elem.getDeliveryStatus()));
    }

    deleteUser(reg.getAccountId());
    properties.setDisable(false);
  }

  @Test
  public void testSendMultipleNotifications() {

    int count = 3;
    List<RegistrationRequestDto> requestList = new ArrayList<>();

    for (int idx = 1; idx <= count; idx++) {
      RegistrationRequestDto reg = createRegistrationRequest("test_user_" + idx);
      requestList.add(reg);
    }

    notificationService.sendPendingNotification();

    Assert.assertTrue("element count", wiser.getMessages().size() == count);
    Iterable<IamEmailNotification> queue = notificationRepository.findAll();
    for (IamEmailNotification elem : queue) {
      Assert.assertTrue("status", IamDeliveryStatus.DELIVERED.equals(elem.getDeliveryStatus()));
    }

    for (RegistrationRequestDto elem : requestList) {
      deleteUser(elem.getAccountId());
    }
  }

  @Test
  public void testSendWithEmptyQueue() {

    notificationService.sendPendingNotification();
    Assert.assertTrue("element count", wiser.getMessages().size() == 0);
  }

  @Test
  public void testDeliveryFailure() {
    String username = "test_user";
    RegistrationRequestDto reg = createRegistrationRequest(username);

    wiser.stop();

    notificationService.sendPendingNotification();

    Iterable<IamEmailNotification> queue = notificationRepository.findAll();
    for (IamEmailNotification elem : queue) {
      Assert.assertTrue("status",
          IamDeliveryStatus.DELIVERY_ERROR.equals(elem.getDeliveryStatus()));
    }

    deleteUser(reg.getAccountId());
  }


  @Test
  public void testApproveFlowNotifications() throws MessagingException {
    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);
    notificationService.sendPendingNotification();

    Assert.assertTrue("element count", wiser.getMessages().size() == 1);
    WiserMessage message = wiser.getMessages().get(0);
    Assert.assertTrue("subject confirmation",
        properties.getSubject().get("confirmation").equals(message.getMimeMessage().getSubject()));

    String confirmationKey = generator.getLastToken();
    confirmRegistrationRequest(confirmationKey);
    notificationService.sendPendingNotification();

    Assert.assertTrue("element count after confirm", wiser.getMessages().size() == 2);
    message = wiser.getMessages().get(1);
    Assert.assertTrue("subject handle", properties.getSubject()
      .get("adminHandleRequest")
      .equals(message.getMimeMessage().getSubject()));
    Assert.assertTrue("receiver",
        message.getEnvelopeReceiver().startsWith(properties.getAdminAddress()));

    RegistrationUtils.approveRequest(reg.getUuid());
    notificationService.sendPendingNotification();

    Assert.assertTrue("element count after approve", wiser.getMessages().size() == 3);
    message = wiser.getMessages().get(2);
    Assert.assertTrue("subject activated",
        properties.getSubject().get("activated").equals(message.getMimeMessage().getSubject()));

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testRejectFlowNotifications() throws MessagingException {
    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);
    notificationService.sendPendingNotification();

    Assert.assertTrue("element count", wiser.getMessages().size() == 1);
    WiserMessage message = wiser.getMessages().get(0);
    Assert.assertTrue("subject confirm",
        properties.getSubject().get("confirmation").equals(message.getMimeMessage().getSubject()));

    String confirmationKey = generator.getLastToken();
    confirmRegistrationRequest(confirmationKey);
    notificationService.sendPendingNotification();

    Assert.assertTrue("element count after confirm", wiser.getMessages().size() == 2);
    message = wiser.getMessages().get(1);
    Assert.assertTrue("subject handle", properties.getSubject()
      .get("adminHandleRequest")
      .equals(message.getMimeMessage().getSubject()));
    Assert.assertTrue("receiver",
        message.getEnvelopeReceiver().startsWith(properties.getAdminAddress()));

    RegistrationUtils.rejectRequest(reg.getUuid());
    notificationService.sendPendingNotification();

    Assert.assertTrue("element count after reject", wiser.getMessages().size() == 3);
    message = wiser.getMessages().get(2);
    Assert.assertTrue("subject rejected",
        properties.getSubject().get("rejected").equals(message.getMimeMessage().getSubject()));

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testCleanOldMessages() {
    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);
    notificationService.sendPendingNotification();
    Assert.assertTrue("element count", wiser.getMessages().size() == 1);

    Date fakeDate = DateUtils.addDays(new Date(), (properties.getCleanupAge() + 1));
    timeProvider.setTime(fakeDate.getTime());

    notificationService.clearExpiredNotifications();

    Integer count = notificationRepository.countAllMessages();
    Assert.assertTrue("messages count", count == 0);

    deleteUser(reg.getAccountId());
  }

}
