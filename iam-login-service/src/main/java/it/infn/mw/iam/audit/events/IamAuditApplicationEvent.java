package it.infn.mw.iam.audit.events;

import java.util.Map;

import org.springframework.context.ApplicationEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.google.common.collect.Maps;

public class IamAuditApplicationEvent extends ApplicationEvent {

  private static final long serialVersionUID = -6276169409979227109L;

  private static final String NULL_PRINCIPAL = "none";

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
    getData().put("source", super.source.getClass().getSimpleName());
    getData().put("principal", principal);
    getData().put("message", message);
  }

  protected String printAuditData() {
    addAuditData();
    StringBuilder str = new StringBuilder();
    for (Map.Entry<String, Object> entry : getData().entrySet()) {
      str.append(String.format(" \"%s\": \"%s\",", entry.getKey(), entry.getValue()));
    }
    return str.toString();
  }

  @Override
  public String toString() {
    return String.format("AuditEvent {%s}", printAuditData());
  }

}
