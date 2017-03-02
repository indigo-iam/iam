package it.infn.mw.iam.audit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.audit.events.auth.IamAuthorizationFailureEvent;

@Component
public class IamAuthorizationAuditListener
    implements ApplicationListener<AuthorizationFailureEvent> {

  private final AuditEventLogger logger;

  
  @Autowired
  public IamAuthorizationAuditListener(AuditEventLogger logger) {
    this.logger = logger;
  }
  
  @Override
  public void onApplicationEvent(AuthorizationFailureEvent event) {
    
    logger.logAuditEvent(new IamAuthorizationFailureEvent(event));

  }
  
}

