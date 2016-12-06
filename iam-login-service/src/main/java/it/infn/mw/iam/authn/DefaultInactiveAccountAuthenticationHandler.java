package it.infn.mw.iam.authn;

import static it.infn.mw.iam.core.IamRegistrationRequestStatus.CONFIRMED;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.NEW;

import java.util.EnumSet;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.core.IamProperties;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.persistence.model.IamAccount;

@Component
public class DefaultInactiveAccountAuthenticationHandler
    implements InactiveAccountAuthenticationHander {

  final IamProperties iamProps;

  public static final String ACCOUNT_SUSPENDED_MESSAGE = "Your account is suspended";

  EnumSet<IamRegistrationRequestStatus> ongoingStatus = EnumSet.of(NEW, CONFIRMED);

  public final String WAITING_CONFIRMATION_MSG;
  public final String WAITING_APPROVAL_MSG;

  @Autowired
  public DefaultInactiveAccountAuthenticationHandler(IamProperties properties) {
    this.iamProps = properties;

    WAITING_CONFIRMATION_MSG = String.format("Your registration request to %s was submitted "
        + "successfully, but you haven't confirmed it yet. Check your inbox, you should have received a message with "
        + "a confirmation URL", iamProps.getOrganisationName());

    WAITING_APPROVAL_MSG =
        String.format("Your registration request to %s was submitted and confirmed successfully, "
            + "and is now waiting for administrator approval. As soon as your request is approved you will receive a "
            + "confirmation email", iamProps.getOrganisationName());
  }

  protected boolean hasOngoingRegistrationRequest(IamAccount account) {

    if (account.getRegistrationRequest() != null) {
      if (ongoingStatus.contains(account.getRegistrationRequest().getStatus())) {
        return true;
      }
    }

    return false;

  }

  protected boolean requestWaitingForUserConfirmation(IamAccount account) {
    if (account.getRegistrationRequest() != null) {
      return (NEW.equals(account.getRegistrationRequest().getStatus()));
    }
    return false;
  }

  protected boolean requestWaitingForAdminApproval(IamAccount account) {
    if (account.getRegistrationRequest() != null) {
      return (CONFIRMED.equals(account.getRegistrationRequest().getStatus()));
    }
    return false;
  }

  protected void raiseAuthenticationError(String msg) {
    throw new DisabledException(msg);
  }

  @Override
  public void handleInactiveAccount(IamAccount account) throws UsernameNotFoundException {

    if (account.isActive()) {
      return;
    }

    if (hasOngoingRegistrationRequest(account)) {

      if (requestWaitingForUserConfirmation(account)) {
        raiseAuthenticationError(WAITING_CONFIRMATION_MSG);
      }

      if (requestWaitingForAdminApproval(account)) {
        raiseAuthenticationError(WAITING_APPROVAL_MSG);
      }
    }

    raiseAuthenticationError(ACCOUNT_SUSPENDED_MESSAGE);
  }

}
