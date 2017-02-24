package it.infn.mw.iam.audit.events.registration;

import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public class RegistrationRejectEvent extends RegistrationEvent {

  private static final long serialVersionUID = -8142561937100438433L;

  public RegistrationRejectEvent(Object source, IamRegistrationRequest request, String message) {
    super(source, request, message);
  }
}
