package it.infn.mw.iam.test.notification;

import static it.infn.mw.iam.test.RegistrationUtils.confirmRegistrationRequest;
import static it.infn.mw.iam.test.RegistrationUtils.createRegistrationRequest;
import static it.infn.mw.iam.test.RegistrationUtils.deleteUser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.mail.MessagingException;

import org.apache.commons.lang.time.DateUtils;
import org.hamcrest.Matchers;
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
import it.infn.mw.iam.api.account.password_reset.PasswordResetController;
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

  @Value("${iam.organisation.name}")
  private String organisationName;

  @Value("${iam.baseUrl}")
  private String baseUrl;

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

    notificationRepository.deleteAll();
  }

  @Test
  public void testSendEmails() throws MessagingException {

    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);
    notificationService.sendPendingNotifications();

    Assert.assertEquals(1, wiser.getMessages().size());
    WiserMessage message = wiser.getMessages().get(0);

    Assert.assertEquals(properties.getMailFrom(), message.getEnvelopeSender());
    Assert.assertTrue("receiver", message.getEnvelopeReceiver().startsWith(username));
    Assert.assertEquals(properties.getSubject().get("confirmation"),
        message.getMimeMessage().getSubject());

    Iterable<IamEmailNotification> queue = notificationRepository.findAll();
    for (IamEmailNotification elem : queue) {
      Assert.assertEquals(IamDeliveryStatus.DELIVERED, elem.getDeliveryStatus());
    }

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testDisableNotificationOption() {
    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);

    properties.setDisable(true);
    notificationService.sendPendingNotifications();

    Assert.assertEquals(0, wiser.getMessages().size());

    Iterable<IamEmailNotification> queue = notificationRepository.findAll();
    for (IamEmailNotification elem : queue) {
      Assert.assertEquals(IamDeliveryStatus.DELIVERED, elem.getDeliveryStatus());
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

    notificationService.sendPendingNotifications();

    Assert.assertEquals(count, wiser.getMessages().size());

    Iterable<IamEmailNotification> queue = notificationRepository.findAll();
    for (IamEmailNotification elem : queue) {
      Assert.assertEquals(IamDeliveryStatus.DELIVERED, elem.getDeliveryStatus());
    }

    for (RegistrationRequestDto elem : requestList) {
      deleteUser(elem.getAccountId());
    }
  }

  @Test
  public void testSendWithEmptyQueue() {

    notificationService.sendPendingNotifications();
    Assert.assertEquals(0, wiser.getMessages().size());
  }

  @Test
  public void testDeliveryFailure() {
    String username = "test_user";
    RegistrationRequestDto reg = createRegistrationRequest(username);

    wiser.stop();

    notificationService.sendPendingNotifications();

    Iterable<IamEmailNotification> queue = notificationRepository.findAll();
    for (IamEmailNotification elem : queue) {
      Assert.assertEquals(IamDeliveryStatus.DELIVERY_ERROR, elem.getDeliveryStatus());
    }

    deleteUser(reg.getAccountId());
  }


  @Test
  public void testApproveFlowNotifications() throws MessagingException {
    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);
    notificationService.sendPendingNotifications();

    Assert.assertEquals(1, wiser.getMessages().size());

    WiserMessage message = wiser.getMessages().get(0);

    Assert.assertEquals(message.getMimeMessage().getSubject(),
        properties.getSubject().get("confirmation"));

    String confirmationKey = generator.getLastToken();
    confirmRegistrationRequest(confirmationKey);
    notificationService.sendPendingNotifications();

    Assert.assertEquals(2, wiser.getMessages().size());

    message = wiser.getMessages().get(1);

    Assert.assertEquals(properties.getSubject().get("adminHandleRequest"),
        message.getMimeMessage().getSubject());

    Assert.assertTrue("receiver",
        message.getEnvelopeReceiver().startsWith(properties.getAdminAddress()));

    RegistrationUtils.approveRequest(reg.getUuid());
    notificationService.sendPendingNotifications();

    Assert.assertEquals(3, wiser.getMessages().size());

    message = wiser.getMessages().get(2);

    Assert.assertEquals(properties.getSubject().get("activated"),
        message.getMimeMessage().getSubject());

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testRejectFlowNotifications() throws MessagingException {
    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);
    notificationService.sendPendingNotifications();

    Assert.assertEquals(1, wiser.getMessages().size());

    WiserMessage message = wiser.getMessages().get(0);
    Assert.assertEquals(properties.getSubject().get("confirmation"),
        message.getMimeMessage().getSubject());

    String confirmationKey = generator.getLastToken();
    confirmRegistrationRequest(confirmationKey);
    notificationService.sendPendingNotifications();

    Assert.assertEquals(2, wiser.getMessages().size());
    message = wiser.getMessages().get(1);
    Assert.assertEquals(properties.getSubject().get("adminHandleRequest"),
        message.getMimeMessage().getSubject());
    Assert.assertTrue("receiver",
        message.getEnvelopeReceiver().startsWith(properties.getAdminAddress()));

    RegistrationUtils.rejectRequest(reg.getUuid());
    notificationService.sendPendingNotifications();

    Assert.assertEquals(3, wiser.getMessages().size());

    message = wiser.getMessages().get(2);
    Assert.assertEquals(properties.getSubject().get("rejected"),
        message.getMimeMessage().getSubject());
  }

  @Test
  public void testCleanOldMessages() {
    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);
    notificationService.sendPendingNotifications();
    Assert.assertEquals(1, wiser.getMessages().size());

    Date fakeDate = DateUtils.addDays(new Date(), (properties.getCleanupAge() + 1));
    timeProvider.setTime(fakeDate.getTime());

    notificationService.clearExpiredNotifications();

    deleteUser(reg.getAccountId());

    int count = notificationRepository.countAllMessages();
    Assert.assertEquals(0, count);


  }

  @Test
  public void testEveryMailShouldContainSignature() throws MessagingException, IOException {
    String signature = String.format("The %s registration service", organisationName);

    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);
    String confirmationKey = generator.getLastToken();
    confirmRegistrationRequest(confirmationKey);
    RegistrationUtils.approveRequest(reg.getUuid());

    notificationService.sendPendingNotifications();

    for (WiserMessage message : wiser.getMessages()) {
      Assert.assertTrue("text/plain", message.getMimeMessage().isMimeType("text/plain"));
      String content = message.getMimeMessage().getContent().toString();
      Assert.assertThat(content, Matchers.containsString(signature));
    }

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testConfirmMailShouldContainsConfirmationLink()
      throws MessagingException, IOException {

    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);
    String confirmationKey = generator.getLastToken();

    String confirmURL = String.format("%s/registration/verify/%s", baseUrl, confirmationKey);

    notificationService.sendPendingNotifications();

    WiserMessage message = wiser.getMessages().get(0);

    Assert.assertTrue("text/plain", message.getMimeMessage().isMimeType("text/plain"));
    String content = message.getMimeMessage().getContent().toString();
    Assert.assertThat(content, Matchers.containsString(confirmURL));

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testActivationMailShouldContainsResetPasswordLink()
      throws MessagingException, IOException {

    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);
    String confirmationKey = generator.getLastToken();
    RegistrationUtils.confirmRegistrationRequest(confirmationKey);
    RegistrationUtils.approveRequest(reg.getUuid());
    String resetKey = generator.getLastToken();

    String resetPasswordUrl =
        String.format("%s%s/%s", baseUrl, PasswordResetController.BASE_TOKEN_URL, resetKey);

    notificationService.sendPendingNotifications();

    WiserMessage message = wiser.getMessages().get(2);

    Assert.assertTrue("text/plain", message.getMimeMessage().isMimeType("text/plain"));
    String content = message.getMimeMessage().getContent().toString();
    Assert.assertThat(content, Matchers.containsString(resetPasswordUrl));

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testAdminNotificationMailShouldContainsDashboardLink()
      throws MessagingException, IOException {

    String username = "test_user";

    RegistrationRequestDto reg = createRegistrationRequest(username);
    String confirmationKey = generator.getLastToken();
    RegistrationUtils.confirmRegistrationRequest(confirmationKey);

    String dashboardUrl = String.format("%s/dashboard#/requests", baseUrl);

    notificationService.sendPendingNotifications();

    WiserMessage message = wiser.getMessages().get(1);

    Assert.assertTrue("text/plain", message.getMimeMessage().isMimeType("text/plain"));
    String content = message.getMimeMessage().getContent().toString();
    Assert.assertThat(content, Matchers.containsString(dashboardUrl));

    deleteUser(reg.getAccountId());
  }

}
