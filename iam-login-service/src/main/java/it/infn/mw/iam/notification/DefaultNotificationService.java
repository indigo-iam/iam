package it.infn.mw.iam.notification;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.lang.time.DateUtils;
import org.apache.velocity.app.VelocityEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.velocity.VelocityEngineUtils;

import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamNotificationReceiver;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;

@Service
@Qualifier("defaultNotificationService")
public class DefaultNotificationService implements NotificationService {

  private static final Logger logger = LoggerFactory.getLogger(DefaultNotificationService.class);

  private static final String RECIPIENT_FIELD = "recipient";

  @Autowired
  private VelocityEngine velocityEngine;

  @Autowired
  private JavaMailSender mailSender;

  @Autowired
  private IamEmailNotificationRepository notificationRepository;

  @Autowired
  private NotificationProperties properties;

  @Value("${iam.baseUrl}")
  private String baseUrl;

  @Autowired
  private TimeProvider timeProvider;


  @Override
  public IamEmailNotification createConfirmationMessage(IamRegistrationRequest request) {

    String recipient = request.getAccount().getUserInfo().getName();
    String confirmURL = String.format("%s/registration/verify/%s", baseUrl,
        request.getAccount().getConfirmationKey());

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put("confirmURL", confirmURL);

    return createMessage("confirmRegistration.vm", model, IamNotificationType.CONFIRMATION,
        properties.getSubject().get("confirmation"), request,
        request.getAccount().getUserInfo().getEmail());
  }

  @Override
  public IamEmailNotification createAccountActivatedMessage(IamRegistrationRequest request) {

    String recipient = request.getAccount().getUserInfo().getName();
    String resetPasswordUrl =
        String.format("%s/iam/password-reset/%s", baseUrl, request.getAccount().getResetKey());

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put("resetPasswordUrl", resetPasswordUrl);

    return createMessage("accountActivated.vm", model, IamNotificationType.ACTIVATED,
        properties.getSubject().get("activated"), request,
        request.getAccount().getUserInfo().getEmail());
  }

  @Override
  public IamEmailNotification createRequestRejectedMessage(IamRegistrationRequest request) {
    String recipient = request.getAccount().getUserInfo().getName();

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);

    return createMessage("requestRejected.vm", model, IamNotificationType.REJECTED,
        properties.getSubject().get("rejected"), request,
        request.getAccount().getUserInfo().getEmail());
  }

  @Override
  public IamEmailNotification createAdminHandleRequestMessage(IamRegistrationRequest request) {
    String name = request.getAccount().getUserInfo().getName();
    String username = request.getAccount().getUsername();
    String email = request.getAccount().getUserInfo().getEmail();

    Map<String, Object> model = new HashMap<>();
    model.put("name", name);
    model.put("username", username);
    model.put("email", email);

    return createMessage("adminHandleRequest.vm", model, IamNotificationType.CONFIRMATION,
        properties.getSubject().get("adminHandleRequest"), request, properties.getAdminAddress());
  }

  @Override
  public IamEmailNotification createResetPasswordMessage(IamAccount account) {

    String recipient = account.getUserInfo().getName();
    String resetPasswordUrl =
        String.format("%s/iam/password-reset/%s", baseUrl, account.getResetKey());

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put("resetPasswordUrl", resetPasswordUrl);

    return createMessage("resetPassword.vm", model, IamNotificationType.RESETPASSWD,
        properties.getSubject().get("resetPassword"), null, account.getUserInfo().getEmail());
  }

  @Override
  @Transactional
  public void sendPendingNotification() {

    SimpleMailMessage messageTemplate = new SimpleMailMessage();
    messageTemplate.setFrom(properties.getMailFrom());

    List<IamEmailNotification> messageQueue =
        notificationRepository.findByDeliveryStatus(IamDeliveryStatus.PENDING);

    for (IamEmailNotification elem : messageQueue) {
      messageTemplate.setSubject(elem.getSubject());
      messageTemplate.setText(elem.getBody());

      for (IamNotificationReceiver receiver : elem.getReceivers()) {
        messageTemplate.setTo(receiver.getEmailAddress());
      }

      try {
        doSend(messageTemplate);

        elem.setDeliveryStatus(IamDeliveryStatus.DELIVERED);

        logger.info("Sent mail. message_id:{} status:{} message_type:{} mail_from:{} rcpt_to:{}",
            elem.getUuid(), elem.getDeliveryStatus().name(), elem.getType(),
            properties.getMailFrom(), messageTemplate.getTo());

      } catch (MailException me) {
        elem.setDeliveryStatus(IamDeliveryStatus.DELIVERY_ERROR);
        logger.error("Message delivery fail. message_id:{} reason:{}", elem.getUuid(),
            me.getMessage());
      }

      elem.setLastUpdate(new Date());
      notificationRepository.save(elem);
    }
  }

  @Override
  public void clearExpiredNotifications() {

    Date currentTime = new Date(timeProvider.currentTimeMillis());
    Date threshold = DateUtils.addDays(currentTime, -properties.getCleanupAge());

    List<IamEmailNotification> messageList =
        notificationRepository.findByStatusWithUpdateTime(IamDeliveryStatus.DELIVERED, threshold);

    if (!messageList.isEmpty()) {
      notificationRepository.delete(messageList);
      logger.info("Deleted {} messages in status {} older than {}", messageList.size(),
          IamDeliveryStatus.DELIVERED, threshold);
    }
  }


  protected void doSend(final SimpleMailMessage message) {
    if (!properties.getDisable()) {
      mailSender.send(message);
    } else {
      logger.info("Notification disabled: message {}", message);
    }
  }


  private IamEmailNotification createMessage(String template, Map<String, Object> model,
      IamNotificationType messageType, String subject, IamRegistrationRequest request,
      String receiverAddress) {

    String body =
        VelocityEngineUtils.mergeTemplateIntoString(velocityEngine, template, "UTF-8", model);

    IamEmailNotification message = new IamEmailNotification();
    message.setUuid(UUID.randomUUID().toString());
    message.setType(messageType);
    message.setSubject(subject);
    message.setBody(body);
    message.setCreationTime(new Date());
    message.setDeliveryStatus(IamDeliveryStatus.PENDING);
    message.setRequest(request);

    List<IamNotificationReceiver> receivers = new ArrayList<>();
    IamNotificationReceiver rcv = new IamNotificationReceiver();
    rcv.setIamEmailNotification(message);
    rcv.setEmailAddress(receiverAddress);
    receivers.add(rcv);

    message.setReceivers(receivers);

    notificationRepository.save(message);

    return message;
  }

}
