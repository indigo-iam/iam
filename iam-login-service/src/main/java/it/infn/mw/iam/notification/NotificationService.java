package it.infn.mw.iam.notification;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public interface NotificationService {

  public IamEmailNotification createConfirmationMessage(IamRegistrationRequest request);

  public IamEmailNotification createAccountActivatedMessage(IamRegistrationRequest request);

  public IamEmailNotification createRequestRejectedMessage(IamRegistrationRequest request);

  public IamEmailNotification createAdminHandleRequestMessage(IamRegistrationRequest request);

  public IamEmailNotification createResetPasswordMessage(IamAccount account);

  public void sendPendingNotification();

  public void clearExpiredNotifications();

}
