package it.infn.mw.iam.audit.events;

import static it.infn.mw.iam.audit.IamAuditField.category;
import static it.infn.mw.iam.audit.IamAuditField.requestStatus;
import static it.infn.mw.iam.audit.IamAuditField.requestUuid;
import static it.infn.mw.iam.audit.IamAuditField.type;
import static it.infn.mw.iam.audit.IamAuditField.user;

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
    getData().put(category, categoryValue);
    getData().put(type, this.getClass().getSimpleName());
    getData().put(requestUuid, request.getUuid());
    getData().put(requestStatus, request.getStatus());
    getData().put(user, request.getAccount().getUsername());
  }
}
