package it.infn.mw.iam.audit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.audit.events.auth.IamAuthenticationEvent;

@Component
public class IamAuthenticationAuditListener
    implements ApplicationListener<AbstractAuthenticationEvent> {

  private final AuditEventLogger logger;

  private IamAuthenticationEvent lastEvent;
  
  @Autowired
  public IamAuthenticationAuditListener(AuditEventLogger logger) {
    this.logger = logger;
  }

  @Override
  public void onApplicationEvent(AbstractAuthenticationEvent event) {

    lastEvent = new IamAuthenticationEvent(event);
    logger.logAuditEvent(lastEvent);

  }  
  
  public IamAuthenticationEvent getLastEvent() {
    return lastEvent;
  }

}

