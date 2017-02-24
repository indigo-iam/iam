package it.infn.mw.iam.audit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.access.event.AbstractAuthorizationEvent;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.audit.events.auth.IamAuthorizationEvent;

@Component
public class IamAuthorizationAuditListener
    implements ApplicationListener<AbstractAuthorizationEvent> {

  private final AuditEventLogger logger;

  private IamAuthorizationEvent lastEvent;
  
  @Autowired
  public IamAuthorizationAuditListener(AuditEventLogger logger) {
    this.logger = logger;
  }
  
  @Override
  public void onApplicationEvent(AbstractAuthorizationEvent event) {

    lastEvent = new IamAuthorizationEvent(event);
    logger.logAuditEvent(lastEvent);

  }

  public IamAuthorizationEvent getLastEvent() {
    return lastEvent;
  }
}

