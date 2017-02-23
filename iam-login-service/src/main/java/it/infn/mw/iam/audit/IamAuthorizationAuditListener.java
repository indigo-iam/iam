package it.infn.mw.iam.audit;

import static it.infn.mw.iam.audit.IamAuditField.category;
import static it.infn.mw.iam.audit.IamAuditField.failureType;
import static it.infn.mw.iam.audit.IamAuditField.message;
import static it.infn.mw.iam.audit.IamAuditField.principal;
import static it.infn.mw.iam.audit.IamAuditField.source;
import static it.infn.mw.iam.audit.IamAuditField.type;
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

    data = Maps.newLinkedHashMap();
    data.put(source, event.getSource().getClass().getSimpleName());
    data.put(category, AUTHZ_CATEGORY);
    data.put(type, event.getClass().getSimpleName());

    if (event instanceof AuthenticationCredentialsNotFoundEvent) {
      AuthenticationCredentialsNotFoundEvent localEvent =
          (AuthenticationCredentialsNotFoundEvent) event;
      data.put(principal, NULL_PRINCIPAL);
      data.put(failureType,
          localEvent.getCredentialsNotFoundException().getClass().getSimpleName());
      data.put(message, localEvent.getCredentialsNotFoundException().getMessage());

    } else if (event instanceof AuthorizationFailureEvent) {
      AuthorizationFailureEvent localEvent = (AuthorizationFailureEvent) event;
      data.put(principal, localEvent.getAuthentication().getName());
      data.put(failureType, localEvent.getAccessDeniedException().getClass().getSimpleName());
      data.put(message, localEvent.getSource().toString());
    }

    logger.info(String.format("AuditEvent: %s", printAuditData(data)));
  }

  public Map<String, Object> getAuditData() {
    return data;
  }
}

