package it.infn.mw.iam.audit.events;

import static it.infn.mw.iam.audit.IamAuditUtils.NULL_PRINCIPAL;

import java.util.Map;

import org.springframework.context.ApplicationEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.google.common.collect.Maps;

import it.infn.mw.iam.audit.IamAuditField;
import it.infn.mw.iam.audit.IamAuditUtils;

public class IamAuditApplicationEvent extends ApplicationEvent {

  private static final long serialVersionUID = -6276169409979227109L;

  private final String principal;
  private final String message;
  private final Map<String, Object> data;

  public IamAuditApplicationEvent(Object source, String message, Map<String, Object> data) {
    super(source);
    this.message = message;
    this.data = data;

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    if (auth == null) {
      this.principal = NULL_PRINCIPAL;
    } else {
      this.principal = auth.getName();
    }
  }

  public IamAuditApplicationEvent(Object source, String message) {
    this(source, message, Maps.newLinkedHashMap());
  }

  public String getPrincipal() {
    return principal;
  }

  public String getMessage() {
    return message;
  }

  public Map<String, Object> getData() {
    return data;
  }

  protected void addAuditData() {
    getData().put(IamAuditField.source, super.source.getClass().getSimpleName());
    getData().put(IamAuditField.principal, principal);
    getData().put(IamAuditField.message, message);
  }

  @Override
  public String toString() {
    addAuditData();
    return String.format("AuditEvent: %s", IamAuditUtils.printAuditData(getData()));
  }

}
