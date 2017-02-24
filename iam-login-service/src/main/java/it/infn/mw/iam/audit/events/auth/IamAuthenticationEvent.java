package it.infn.mw.iam.audit.events.auth;

import static it.infn.mw.iam.audit.IamAuditField.CATEGORY;
import static it.infn.mw.iam.audit.IamAuditField.DETAILS;
import static it.infn.mw.iam.audit.IamAuditField.FAILURE_TYPE;
import static it.infn.mw.iam.audit.IamAuditField.GENERATED_BY;
import static it.infn.mw.iam.audit.IamAuditField.MESSAGE;
import static it.infn.mw.iam.audit.IamAuditField.PRINCIPAL;
import static it.infn.mw.iam.audit.IamAuditField.SOURCE;
import static it.infn.mw.iam.audit.IamAuditField.TARGET;
import static it.infn.mw.iam.audit.IamAuditField.TYPE;

import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.web.authentication.switchuser.AuthenticationSwitchUserEvent;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;

public class IamAuthenticationEvent extends IamAuditApplicationEvent {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;
  public static final String AUTHN_CATEGORY = "AUTHENTICATION";
  
  final AbstractAuthenticationEvent sourceAuthEvent;
  
  public IamAuthenticationEvent(AbstractAuthenticationEvent authEvent) {
    super(authEvent.getSource());
    this.sourceAuthEvent = authEvent;
  }

  public AbstractAuthenticationEvent getSourceAuthEvent() {
    return sourceAuthEvent;
  }
  
  @Override
  protected void addAuditData() {
    super.addAuditData();
    
    getData().put(CATEGORY, AUTHN_CATEGORY);
    getData().put(SOURCE, sourceAuthEvent.getSource().getClass().getSimpleName());
    getData().put(TYPE, sourceAuthEvent.getClass().getSimpleName());
    getData().put(PRINCIPAL, sourceAuthEvent.getAuthentication().getName());
    
    if (sourceAuthEvent.getAuthentication().getDetails() != null) {
      getData().put(DETAILS, sourceAuthEvent.getAuthentication().getDetails());
    }

    if (sourceAuthEvent instanceof AbstractAuthenticationFailureEvent) {
      AbstractAuthenticationFailureEvent localEvent = (AbstractAuthenticationFailureEvent) 
          sourceAuthEvent;
      getData().put(FAILURE_TYPE, localEvent.getException().getClass().getSimpleName());
      getData().put(MESSAGE, localEvent.getException().getMessage());

    } else if (sourceAuthEvent instanceof AuthenticationSwitchUserEvent) {
      AuthenticationSwitchUserEvent localEvent = (AuthenticationSwitchUserEvent) sourceAuthEvent;
      getData().put(TARGET, localEvent.getTargetUser().getUsername());
    } else if (sourceAuthEvent instanceof InteractiveAuthenticationSuccessEvent) {
      InteractiveAuthenticationSuccessEvent localEvent =
          (InteractiveAuthenticationSuccessEvent) sourceAuthEvent;
      getData().put(GENERATED_BY, localEvent.getGeneratedBy().getSimpleName());
    }
    
  }
}
