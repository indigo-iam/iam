package it.infn.mw.iam.audit;

import static it.infn.mw.iam.audit.IamAuditField.CATEGORY;
import static it.infn.mw.iam.audit.IamAuditField.FAILURE_TYPE;
import static it.infn.mw.iam.audit.IamAuditField.MESSAGE;
import static it.infn.mw.iam.audit.IamAuditField.PRINCIPAL;
import static it.infn.mw.iam.audit.IamAuditField.SOURCE;
import static it.infn.mw.iam.audit.IamAuditField.TYPE;
import static it.infn.mw.iam.audit.IamAuditUtils.AUTHZ_CATEGORY;
import static it.infn.mw.iam.audit.IamAuditUtils.NULL_PRINCIPAL;
import static it.infn.mw.iam.audit.IamAuditUtils.printAuditData;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.security.access.event.AbstractAuthorizationEvent;
import org.springframework.security.access.event.AuthenticationCredentialsNotFoundEvent;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.stereotype.Component;

import com.google.common.collect.Maps;

@Component
public class IamAuthorizationAuditListener
    implements ApplicationListener<AbstractAuthorizationEvent> {

  private static final Log logger = LogFactory.getLog(IamAuthorizationAuditListener.class);


  private Map<String, Object> data = Maps.newLinkedHashMap();

  @Override
  public void onApplicationEvent(AbstractAuthorizationEvent event) {

    data.clear();
    data.put(SOURCE, event.getSource().getClass().getSimpleName());
    data.put(CATEGORY, AUTHZ_CATEGORY);
    data.put(TYPE, event.getClass().getSimpleName());

    if (event instanceof AuthenticationCredentialsNotFoundEvent) {
      AuthenticationCredentialsNotFoundEvent localEvent =
          (AuthenticationCredentialsNotFoundEvent) event;
      data.put(PRINCIPAL, NULL_PRINCIPAL);
      data.put(FAILURE_TYPE,
          localEvent.getCredentialsNotFoundException().getClass().getSimpleName());
      data.put(MESSAGE, localEvent.getCredentialsNotFoundException().getMessage());

    } else if (event instanceof AuthorizationFailureEvent) {
      AuthorizationFailureEvent localEvent = (AuthorizationFailureEvent) event;
      data.put(PRINCIPAL, localEvent.getAuthentication().getName());
      data.put(FAILURE_TYPE, localEvent.getAccessDeniedException().getClass().getSimpleName());
      data.put(MESSAGE, localEvent.getSource().toString());
    }

    logger.info(String.format("AuditEvent: %s", printAuditData(data)));
  }

  public Map<String, Object> getAuditData() {
    return data;
  }
}

