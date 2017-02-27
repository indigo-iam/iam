package it.infn.mw.iam.audit.events.auth;

import static it.infn.mw.iam.audit.IamAuditField.CATEGORY;
import static it.infn.mw.iam.audit.IamAuditField.FAILURE_TYPE;
import static it.infn.mw.iam.audit.IamAuditField.MESSAGE;
import static it.infn.mw.iam.audit.IamAuditField.PRINCIPAL;
import static it.infn.mw.iam.audit.IamAuditField.SOURCE;
import static it.infn.mw.iam.audit.IamAuditField.TYPE;

import org.springframework.security.access.event.AbstractAuthorizationEvent;
import org.springframework.security.access.event.AuthenticationCredentialsNotFoundEvent;
import org.springframework.security.access.event.AuthorizationFailureEvent;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;

public class IamAuthorizationEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = 1L;
  public static final String AUTHZ_CATEGORY = "AUTHORIZATION";

  final AbstractAuthorizationEvent sourceAuthzEvent;

  public IamAuthorizationEvent(AbstractAuthorizationEvent event) {
    super(IamEventCategory.AUTHORIZATION,event.getSource());
    this.sourceAuthzEvent = event;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();

    getData().put(SOURCE, sourceAuthzEvent.getSource().getClass().getSimpleName());
    getData().put(CATEGORY, AUTHZ_CATEGORY);
    getData().put(TYPE, sourceAuthzEvent.getClass().getSimpleName());

    if (sourceAuthzEvent instanceof AuthenticationCredentialsNotFoundEvent) {
      AuthenticationCredentialsNotFoundEvent localEvent =
          (AuthenticationCredentialsNotFoundEvent) sourceAuthzEvent;
      getData().put(PRINCIPAL, NULL_PRINCIPAL);
      getData().put(FAILURE_TYPE,
          localEvent.getCredentialsNotFoundException().getClass().getSimpleName());
      getData().put(MESSAGE, localEvent.getCredentialsNotFoundException().getMessage());

    } else if (sourceAuthzEvent instanceof AuthorizationFailureEvent) {
      AuthorizationFailureEvent localEvent = (AuthorizationFailureEvent) sourceAuthzEvent;
      getData().put(PRINCIPAL, localEvent.getAuthentication().getName());
      getData().put(FAILURE_TYPE, localEvent.getAccessDeniedException().getClass().getSimpleName());
      getData().put(MESSAGE, localEvent.getSource().toString());
    }

  }
}
