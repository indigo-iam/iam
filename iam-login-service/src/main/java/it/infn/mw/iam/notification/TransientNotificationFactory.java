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
package it.infn.mw.iam.notification;

import static java.util.Arrays.asList;

import java.io.IOException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ui.freemarker.FreeMarkerTemplateUtils;

import com.google.common.collect.Lists;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import it.infn.mw.iam.api.account.password_reset.PasswordResetController;
import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.notification.service.resolver.AdminNotificationDeliveryStrategy;
import it.infn.mw.iam.notification.service.resolver.GroupManagerNotificationDeliveryStrategy;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamCertLinkRequest;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamGroupRequest;
import it.infn.mw.iam.persistence.model.IamNotificationReceiver;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public class TransientNotificationFactory implements NotificationFactory {

  private static final Logger LOG = LoggerFactory.getLogger(TransientNotificationFactory.class);
  private static final String RECIPIENT_FIELD = "recipient";
  private static final String ORGANISATION_NAME = "organisationName";
  private static final String USERNAME_FIELD = "username";
  private static final String GROUPNAME_FIELD = "groupName";
  private static final String MOTIVATION_FIELD = "motivation";
  private static final String AUP_PATH = "%s/iam/aup/sign";
  private static final String AUP_URL = "aupUrl";
  private static final String DASHBOARD_FIELD = "indigoDashboardUrl";
  private static final String DASHBOARD_URL_TEMPLATE = "%s/dashboard#!/requests";
  private static final String NAME_FIELD = "name";
  private static final String NOTES_FIELD = "notes";
  private static final String STATUS_FIELD = "status";
  private static final String SUBJECT_FIELD = "subject";
  private static final String ISSUER_FIELD = "issuer";


  @Value("${iam.baseUrl}")
  private String baseUrl;

  @Value("${iam.organisation.name}")
  private String organisationName;

  private final NotificationProperties properties;
  private final AdminNotificationDeliveryStrategy adminNotificationDeliveryStrategy;
  private final GroupManagerNotificationDeliveryStrategy groupManagerDeliveryStrategy;
  private final Configuration freeMarkerConfiguration;

  @Autowired
  public TransientNotificationFactory(Configuration fm, NotificationProperties np,
      AdminNotificationDeliveryStrategy ands, GroupManagerNotificationDeliveryStrategy gmds) {
    this.freeMarkerConfiguration = fm;
    this.properties = np;
    this.adminNotificationDeliveryStrategy = ands;
    this.groupManagerDeliveryStrategy = gmds;
  }

  @Override
  public IamEmailNotification createConfirmationMessage(IamRegistrationRequest request) {

    String recipient = request.getAccount().getUserInfo().getName();
    String confirmURL = String.format("%s/registration/verify/%s", baseUrl,
        request.getAccount().getConfirmationKey());

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put("confirmURL", confirmURL);
    model.put(ORGANISATION_NAME, organisationName);

    IamEmailNotification notification = createMessage("confirmRegistration.ftl", model,
        IamNotificationType.CONFIRMATION, properties.getSubject().get("confirmation"),
        asList(request.getAccount().getUserInfo().getEmail()));

    LOG.debug("Created confirmation message for registration request {}. Confirmation URL: {}",
        request.getUuid(), confirmURL);

    return notification;
  }

  @Override
  public IamEmailNotification createAccountActivatedMessage(IamRegistrationRequest request) {

    String recipient = request.getAccount().getUserInfo().getName();
    String resetPasswordUrl = String.format("%s%s/%s", baseUrl,
        PasswordResetController.BASE_TOKEN_URL, request.getAccount().getResetKey());

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);

    model.put("resetPasswordUrl", resetPasswordUrl);
    model.put(ORGANISATION_NAME, organisationName);
    model.put(USERNAME_FIELD, request.getAccount().getUsername());

    IamEmailNotification notification = createMessage("accountActivated.ftl", model,
        IamNotificationType.ACTIVATED, properties.getSubject().get("activated"),
        asList(request.getAccount().getUserInfo().getEmail()));

    LOG.debug(
        "Create account activated message for registration request {}. Reset password URL: {}",
        request.getUuid(), resetPasswordUrl);

    return notification;
  }

  @Override
  public IamEmailNotification createRequestRejectedMessage(IamRegistrationRequest request,
      Optional<String> motivation) {
    String recipient = request.getAccount().getUserInfo().getName();

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put(ORGANISATION_NAME, organisationName);

    if (motivation.isPresent()) {
      model.put(MOTIVATION_FIELD, motivation.get());
    }

    return createMessage("requestRejected.ftl", model, IamNotificationType.REJECTED,
        properties.getSubject().get("rejected"),
        asList(request.getAccount().getUserInfo().getEmail()));
  }

  @Override
  public IamEmailNotification createAdminHandleRequestMessage(IamRegistrationRequest request) {
    String name = request.getAccount().getUserInfo().getName();
    String username = request.getAccount().getUsername();
    String email = request.getAccount().getUserInfo().getEmail();

    Map<String, Object> model = new HashMap<>();
    model.put(NAME_FIELD, name);
    model.put(USERNAME_FIELD, username);
    model.put("email", email);
    model.put(DASHBOARD_FIELD, String.format(DASHBOARD_URL_TEMPLATE, baseUrl));
    model.put(ORGANISATION_NAME, organisationName);
    model.put(NOTES_FIELD, request.getNotes());

    return createMessage("adminHandleRequest.ftl", model, IamNotificationType.CONFIRMATION,
        properties.getSubject().get("adminHandleRequest"),
        adminNotificationDeliveryStrategy.resolveAdminEmailAddresses());
  }

  @Override
  public IamEmailNotification createResetPasswordMessage(IamAccount account) {

    String recipient = account.getUserInfo().getName();
    String resetPasswordUrl = String.format("%s%s/%s", baseUrl,
        PasswordResetController.BASE_TOKEN_URL, account.getResetKey());

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put("resetPasswordUrl", resetPasswordUrl);
    model.put(ORGANISATION_NAME, organisationName);
    model.put(USERNAME_FIELD, account.getUsername());

    IamEmailNotification notification =
        createMessage("resetPassword.ftl", model, IamNotificationType.RESETPASSWD,
            properties.getSubject().get("resetPassword"), asList(account.getUserInfo().getEmail()));

    LOG.debug("Created reset password message for account {}. Reset password URL: {}",
        account.getUsername(), resetPasswordUrl);

    return notification;
  }

  @Override
  public IamEmailNotification createAdminHandleGroupRequestMessage(IamGroupRequest groupRequest) {
    String groupName = groupRequest.getGroup().getName();

    Map<String, Object> model = new HashMap<>();
    model.put(NAME_FIELD, groupRequest.getAccount().getUserInfo().getName());
    model.put(USERNAME_FIELD, groupRequest.getAccount().getUsername());
    model.put(GROUPNAME_FIELD, groupName);
    model.put(NOTES_FIELD, groupRequest.getNotes());
    model.put(DASHBOARD_FIELD, String.format(DASHBOARD_URL_TEMPLATE, baseUrl));
    model.put(ORGANISATION_NAME, organisationName);

    String subject = String.format("New membership request for group %s", groupName);

    LOG.debug("Create group membership admin notification for request {}", groupRequest.getUuid());
    return createMessage("adminHandleGroupRequest.ftl", model, IamNotificationType.GROUP_MEMBERSHIP,
        subject,
        groupManagerDeliveryStrategy.resolveGroupManagersEmailAddresses(groupRequest.getGroup()));
  }

  @Override
  public IamEmailNotification createGroupMembershipApprovedMessage(IamGroupRequest groupRequest) {
    String recipient = groupRequest.getAccount().getUserInfo().getName();
    String groupName = groupRequest.getGroup().getName();
    String status = groupRequest.getStatus().name();

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put(GROUPNAME_FIELD, groupName);
    model.put(STATUS_FIELD, status);
    model.put(ORGANISATION_NAME, organisationName);

    String subject =
        String.format("Membership request for group %s has been %s", groupName, status);

    IamEmailNotification notification =
        createMessage("groupMembershipApproved.ftl", model, IamNotificationType.GROUP_MEMBERSHIP,
            subject, asList(groupRequest.getAccount().getUserInfo().getEmail()));

    LOG.debug("Create group membership approved message for request {}", groupRequest.getUuid());
    return notification;
  }

  @Override
  public IamEmailNotification createGroupMembershipRejectedMessage(IamGroupRequest groupRequest) {
    String recipient = groupRequest.getAccount().getUserInfo().getName();
    String groupName = groupRequest.getGroup().getName();
    String status = groupRequest.getStatus().name();

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put(GROUPNAME_FIELD, groupName);
    model.put(STATUS_FIELD, status);
    model.put(MOTIVATION_FIELD, groupRequest.getMotivation());
    model.put(ORGANISATION_NAME, organisationName);

    String subject =
        String.format("Membership request for group %s has been %s", groupName, status);

    IamEmailNotification notification =
        createMessage("groupMembershipRejected.ftl", model, IamNotificationType.GROUP_MEMBERSHIP,
            subject, asList(groupRequest.getAccount().getUserInfo().getEmail()));

    LOG.debug("Create group membership approved message for request {}", groupRequest.getUuid());
    return notification;
  }

  @Override
  public IamEmailNotification createClientStatusChangedMessageFor(ClientDetailsEntity client,
      List<IamAccount> accounts) {
    Set<String> recipients = client.getContacts();

    Map<String, Object> model = new HashMap<>();
    model.put("clientId", client.getClientId());
    model.put("clientName", client.getClientName());
    model.put("isClientActive", client.isActive());
    model.put(ORGANISATION_NAME, organisationName);

    String subject = "Changed client status";

    for (IamAccount a : accounts) {
      recipients.add(a.getUserInfo().getEmail());
    }

    List<String> emails = Lists.newArrayList(recipients);

    if (emails.isEmpty()) {
      LOG.warn("No email to send notification to for client {}", client.getClientId());
      return null;
    }

    IamEmailNotification notification = createMessage("clientStatusChanged.ftl", model,
        IamNotificationType.CLIENT_STATUS, subject, emails);

    LOG.debug("Updated client status. Client id {}, active {}", client.getClientId(),
        client.isActive());
    return notification;
  }

  @Override
  public IamEmailNotification createAupReminderMessage(IamAccount account, IamAup aup) {
    String recipient = account.getUserInfo().getName();
    String aupUrl = String.format(AUP_PATH, baseUrl);

    LocalDate now = LocalDate.now();
    long signatureValidityInDays = aup.getSignatureValidityInDays();
    LocalDate signatureTime = account.getAupSignature()
      .getSignatureTime()
      .toInstant()
      .atZone(ZoneId.systemDefault())
      .toLocalDate();
    LocalDate signatureValidTime = signatureTime.plusDays(signatureValidityInDays);
    long missingDays = ChronoUnit.DAYS.between(now, signatureValidTime);

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put(AUP_URL, aupUrl);
    model.put(ORGANISATION_NAME, organisationName);
    model.put("missingDays", missingDays);

    String subject = "AUP signature reminder";

    IamEmailNotification notification = createMessage("signAupReminder.ftl", model,
        IamNotificationType.AUP_REMINDER, subject, asList(account.getUserInfo().getEmail()));

    LOG.debug("Created reminder message for signing the account {} AUP. Signing URL: {}",
        account.getUuid(), aupUrl);

    return notification;
  }

  @Override
  public IamEmailNotification createAupSignatureExpMessage(IamAccount account) {
    String recipient = account.getUserInfo().getName();
    String aupUrl = String.format(AUP_PATH, baseUrl);

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put(AUP_URL, aupUrl);
    model.put(ORGANISATION_NAME, organisationName);

    String subject = "AUP signature expiration";

    IamEmailNotification notification = createMessage("aupExpirationMessage.ftl", model,
        IamNotificationType.AUP_EXPIRATION, subject, asList(account.getUserInfo().getEmail()));

    LOG.debug("Created AUP expiration message for the account {}. AUP signing URL: {}",
        account.getUuid(), aupUrl);

    return notification;

  }

  @Override
  public IamEmailNotification createAupSignatureRequestMessage(IamAccount account) {
    String recipient = account.getUserInfo().getName();
    String aupUrl = String.format(AUP_PATH, baseUrl);

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put(AUP_URL, aupUrl);
    model.put(ORGANISATION_NAME, organisationName);

    String subject = "AUP signature request";

    IamEmailNotification notification =
        createMessage("aupSignatureRequest.ftl", model, IamNotificationType.AUP_SIGNATURE_REQUEST,
            subject, asList(account.getUserInfo().getEmail()));

    LOG.debug("Created AUP signature request message for the account {}. AUP signing URL: {}",
        account.getUuid(), aupUrl);

    return notification;
  }

  @Override
  public IamEmailNotification createAccountSuspendedMessage(IamAccount account) {
    String recipient = account.getUserInfo().getName();

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put(ORGANISATION_NAME, organisationName);

    String subject = "Account suspended";

    IamEmailNotification notification = createMessage("accountSuspended.ftl", model,
        IamNotificationType.ACCOUNT_SUSPENDED, subject, asList(account.getUserInfo().getEmail()));

    LOG.debug("Created suspension message for the account {}", account.getUuid());

    return notification;
  }

  @Override
  public IamEmailNotification createAccountRestoredMessage(IamAccount account) {
    String recipient = account.getUserInfo().getName();

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put(ORGANISATION_NAME, organisationName);

    String subject = "Account restored";

    IamEmailNotification notification = createMessage("accountRestored.ftl", model,
        IamNotificationType.ACCOUNT_RESTORED, subject, asList(account.getUserInfo().getEmail()));

    LOG.debug("Created restoration message for the account {}", account.getUuid());

    return notification;
  }

  @Override
  public IamEmailNotification createAdminHandleCertLinkRequestMessage(
      IamCertLinkRequest certLinkRequest) {
    String recipient = certLinkRequest.getAccount().getUserInfo().getName();
    String subject = "New certificate linking request";

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put(NAME_FIELD, certLinkRequest.getAccount().getUserInfo().getName());
    model.put(SUBJECT_FIELD, certLinkRequest.getCertificate().getSubjectDn());
    model.put(ISSUER_FIELD, certLinkRequest.getCertificate().getIssuerDn());
    model.put(USERNAME_FIELD, certLinkRequest.getAccount().getUsername());
    model.put(NOTES_FIELD, certLinkRequest.getNotes());
    model.put(DASHBOARD_FIELD, String.format(DASHBOARD_URL_TEMPLATE, baseUrl));
    model.put(ORGANISATION_NAME, organisationName);

    return createMessage("adminHandleCertLinkRequest.ftl", model,
        IamNotificationType.CERTIFICATE_LINK, subject,
        adminNotificationDeliveryStrategy.resolveAdminEmailAddresses());
  }

  @Override
  public IamEmailNotification createCertLinkApprovedMessage(IamCertLinkRequest certLinkRequest) {
    String recipient = certLinkRequest.getAccount().getUserInfo().getName();
    String subject = "Certificate linking request approved";

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put(NAME_FIELD, certLinkRequest.getAccount().getUserInfo().getName());
    model.put(SUBJECT_FIELD, certLinkRequest.getCertificate().getSubjectDn());
    model.put(ISSUER_FIELD, certLinkRequest.getCertificate().getIssuerDn());
    model.put(STATUS_FIELD, certLinkRequest.getStatus().name());
    model.put(USERNAME_FIELD, certLinkRequest.getAccount().getUsername());
    model.put(ORGANISATION_NAME, organisationName);

    return createMessage("certLinkApproved.ftl", model, IamNotificationType.CERTIFICATE_LINK,
        subject, asList(certLinkRequest.getAccount().getUserInfo().getEmail()));
  }

  @Override
  public IamEmailNotification createCertLinkRejectedMessage(IamCertLinkRequest certLinkRequest) {
    String recipient = certLinkRequest.getAccount().getUserInfo().getName();
    String subject = "Certificate linking request rejected";

    Map<String, Object> model = new HashMap<>();
    model.put(RECIPIENT_FIELD, recipient);
    model.put(NAME_FIELD, certLinkRequest.getAccount().getUserInfo().getName());
    model.put(SUBJECT_FIELD, certLinkRequest.getCertificate().getSubjectDn());
    model.put(ISSUER_FIELD, certLinkRequest.getCertificate().getIssuerDn());
    model.put(STATUS_FIELD, certLinkRequest.getStatus().name());
    model.put(USERNAME_FIELD, certLinkRequest.getAccount().getUsername());
    model.put(MOTIVATION_FIELD, certLinkRequest.getMotivation());
    model.put(ORGANISATION_NAME, organisationName);

    return createMessage("certLinkRejected.ftl", model, IamNotificationType.CERTIFICATE_LINK,
        subject, asList(certLinkRequest.getAccount().getUserInfo().getEmail()));
  }

  protected IamEmailNotification createMessage(String templateName, Map<String, Object> model,
      IamNotificationType messageType, String subject, List<String> receiverAddress) {

    try {
      String formattedSubject = String.format("[%s IAM] %s", organisationName, subject);
      Template template = freeMarkerConfiguration.getTemplate(templateName);
      String body = FreeMarkerTemplateUtils.processTemplateIntoString(template, model);

      IamEmailNotification message = new IamEmailNotification();

      message.setUuid(UUID.randomUUID().toString());
      message.setType(messageType);
      message.setSubject(formattedSubject);
      message.setBody(body);
      message.setCreationTime(new Date());
      message.setDeliveryStatus(IamDeliveryStatus.PENDING);
      message.setReceivers(receiverAddress.stream()
        .map(a -> IamNotificationReceiver.forAddress(message, a))
        .collect(Collectors.toList()));

      return message;
    } catch (IOException | TemplateException e) {
      LOG.error("Exception encountered when attempting to create message: {}", e.toString());
      return null;
    }
  }
}
