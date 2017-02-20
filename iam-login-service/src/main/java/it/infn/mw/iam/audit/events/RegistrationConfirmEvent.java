package it.infn.mw.iam.audit.events;

import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public class RegistrationConfirmEvent extends RegistrationEvent {

  private static final long serialVersionUID = 8266010241487555711L;

  public RegistrationConfirmEvent(Object source, IamRegistrationRequest request, String message) {
    super(source, request, message);
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put("confirmationKey", getRequest().getAccount().getConfirmationKey());
  }

}
