package it.infn.mw.iam.audit.events.registration;

import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public class RegistrationRequestEvent extends RegistrationEvent {

  private static final long serialVersionUID = 1867648607664919759L;

  public RegistrationRequestEvent(Object source, IamRegistrationRequest request, String message) {
    super(source, request, message);
  }
}
