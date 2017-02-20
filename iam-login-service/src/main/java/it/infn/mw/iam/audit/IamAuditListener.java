package it.infn.mw.iam.audit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.actuate.audit.listener.AuditListener;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;

@Component
public class IamAuditListener implements ApplicationListener<IamAuditApplicationEvent> {

  private static final Log logger = LogFactory.getLog(AuditListener.class);

  @Override
  public void onApplicationEvent(IamAuditApplicationEvent event) {

    logger.info(event);
  }

}

