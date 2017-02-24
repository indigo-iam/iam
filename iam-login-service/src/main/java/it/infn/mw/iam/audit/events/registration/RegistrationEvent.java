package it.infn.mw.iam.audit.events.registration;

import static it.infn.mw.iam.audit.IamAuditField.CATEGORY;
import static it.infn.mw.iam.audit.IamAuditField.REQUEST_STATUS;
import static it.infn.mw.iam.audit.IamAuditField.REQUEST_UUID;
import static it.infn.mw.iam.audit.IamAuditField.TYPE;
import static it.infn.mw.iam.audit.IamAuditField.USER;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public class RegistrationEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = -3428745338283606683L;

  private static final String categoryValue = "REGISTRATION";

  private final IamRegistrationRequest request;

  public RegistrationEvent(Object source, IamRegistrationRequest request, String message) {
    super(source, message);
    this.request = request;
  }

  public IamRegistrationRequest getRequest() {
    return request;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put(CATEGORY, categoryValue);
    getData().put(TYPE, this.getClass().getSimpleName());
    getData().put(REQUEST_UUID, request.getUuid());
    getData().put(REQUEST_STATUS, request.getStatus());
    getData().put(USER, request.getAccount().getUsername());
  }
}
