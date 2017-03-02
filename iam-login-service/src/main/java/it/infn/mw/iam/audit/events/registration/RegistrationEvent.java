package it.infn.mw.iam.audit.events.registration;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.utils.IamRegistrationRequestSerializer;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public class RegistrationEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = -3428745338283606683L;

  @JsonSerialize(using=IamRegistrationRequestSerializer.class)
  private final IamRegistrationRequest request;

  public RegistrationEvent(Object source, IamRegistrationRequest request, String message) {
    super(IamEventCategory.REGISTRATION,source, message);
    this.request = request;
  }

  public IamRegistrationRequest getRequest() {
    return request;
  }


}
