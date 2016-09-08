package it.infn.mw.iam.test.notification;

import static it.infn.mw.iam.test.RegistrationUtils.createRegistrationRequest;
import static it.infn.mw.iam.test.RegistrationUtils.deleteUser;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.commons.lang.time.DateUtils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.subethamail.wiser.Wiser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.notification.MockTimeProvider;
import it.infn.mw.iam.notification.NotificationService;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.TestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class NotificationConcurrentTests {

  @Value("${notification.cleanupAge}")
  private Integer notificationCleanUpAge;

  @Value("${spring.mail.host}")
  private String mailHost;

  @Value("${spring.mail.port}")
  private Integer mailPort;

  @Autowired
  private IamEmailNotificationRepository notificationRepository;

  @Autowired
  private NotificationService notificationService;

  @Autowired
  private MockTimeProvider timeProvider;

  private Wiser wiser;

  public static final int NUM_THREADS = 3;
  final CyclicBarrier barrier = new CyclicBarrier(NUM_THREADS + 1);


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
  public void tearDown() {
    wiser.stop();
  }

  @Test
  public void testConcurrentDelivery() throws Exception {

    String username = "test_user";
    RegistrationRequestDto reg = createRegistrationRequest(username);

    ExecutorService executorService = Executors.newFixedThreadPool(NUM_THREADS + 1);
    List<Future<Integer>> futuresList = new ArrayList<>();

    for (int idx = 0; idx < NUM_THREADS; idx++) {
      Future<Integer> result = executorService.submit(new WorkerSend(barrier, notificationService));
      futuresList.add(result);
    }

    barrier.await();
    executorService.shutdown();

    for (Future<Integer> elem : futuresList) {
      elem.get();
    }

    int expected = 1;
    int count = wiser.getMessages().size();

    Assert.assertTrue(String.format("mail sent count. Got [%d] expected [%d]", count, expected),
        count == expected);

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testConcurrentCleanUp() throws Exception {
    String username = "test_user";
    RegistrationRequestDto reg = createRegistrationRequest(username);

    notificationService.sendPendingNotification();
    Assert.assertTrue("element count", wiser.getMessages().size() == 1);

    Date fakeDate = DateUtils.addDays(new Date(), (notificationCleanUpAge + 1));
    timeProvider.setTime(fakeDate.getTime());

    ExecutorService executorService = Executors.newFixedThreadPool(NUM_THREADS + 1);
    List<Future<Integer>> futuresList = new ArrayList<>();

    for (int idx = 0; idx < NUM_THREADS; idx++) {
      Future<Integer> result =
          executorService.submit(new WorkerClean(barrier, notificationService));
      futuresList.add(result);
    }

    barrier.await();
    executorService.shutdown();

    for (Future<Integer> elem : futuresList) {
      elem.get();
    }

    Integer count = notificationRepository.countAllMessages();
    Assert.assertTrue("messages count", count == 0);

    deleteUser(reg.getAccountId());
  }

  public class WorkerSend implements Callable<Integer> {

    private NotificationService notificationService;

    private CyclicBarrier barrier;

    public WorkerSend(CyclicBarrier barrier, NotificationService notificationService) {
      this.barrier = barrier;
      this.notificationService = notificationService;
    }

    @Override
    public Integer call() {
      try {
        barrier.await();
      } catch (Exception ex) {
        ex.printStackTrace();
      }

      this.notificationService.sendPendingNotification();
      return null;
    }
  }

  public class WorkerClean implements Callable<Integer> {

    private NotificationService notificationService;

    private CyclicBarrier barrier;

    public WorkerClean(CyclicBarrier barrier, NotificationService notificationService) {
      this.barrier = barrier;
      this.notificationService = notificationService;
    }

    @Override
    public Integer call() {
      try {
        barrier.await();
      } catch (Exception ex) {
        ex.printStackTrace();
      }

      this.notificationService.clearExpiredNotifications();
      return null;
    }
  }

}
