package it.infn.mw.iam.audit.events.registration;

import static it.infn.mw.iam.audit.IamAuditField.CONFIRMATION_KEY;

import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public class RegistrationConfirmEvent extends RegistrationEvent {

  private static final long serialVersionUID = 8266010241487555711L;

  public RegistrationConfirmEvent(Object source, IamRegistrationRequest request, String message) {
    super(source, request, message);
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put(CONFIRMATION_KEY, getRequest().getAccount().getConfirmationKey());
  }

}
