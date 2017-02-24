package it.infn.mw.iam.audit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;

@Component
public class IamAuditLoggingListener implements ApplicationListener<IamAuditApplicationEvent>
{

  private final AuditEventLogger logger;
  
  @Autowired
  public IamAuditLoggingListener(AuditEventLogger logger) {
    this.logger = logger;
  }

  @Override
  public void onApplicationEvent(IamAuditApplicationEvent event) {

    logger.logAuditEvent(event);
  }
}

