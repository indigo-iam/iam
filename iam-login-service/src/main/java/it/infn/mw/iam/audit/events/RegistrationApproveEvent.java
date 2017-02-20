package it.infn.mw.iam.audit.events;

import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public class RegistrationApproveEvent extends RegistrationEvent {

  private static final long serialVersionUID = -616966571429783703L;

  public RegistrationApproveEvent(Object source, IamRegistrationRequest request, String message) {
    super(source, request, message);
  }

}
