package it.infn.mw.iam.audit.events;



import org.springframework.context.ApplicationEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;

@JsonPropertyOrder({"timestamp", "@type", "category", "principal", "message"})
@JsonTypeInfo(use=Id.NAME, property="@type")
public abstract class IamAuditApplicationEvent extends ApplicationEvent {

  public static enum IamEventCategory {
    NONE,
    ACCOUNT,
    GROUP,
    REGISTRATION,
    AUTHENTICATION,
    AUTHORIZATION
  }

  private static final long serialVersionUID = -6276169409979227109L;
  
  public static final String NULL_PRINCIPAL = "<unknown>";

  @JsonInclude
  private final IamEventCategory category;
  
  @JsonInclude
  private final String principal;
  
  @JsonInclude
  private final String message;
  

  public IamAuditApplicationEvent(IamEventCategory category, Object source, String message) {
    super(source);
    this.message = message;
    this.category = category;
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    if (auth == null) {
      this.principal = NULL_PRINCIPAL;
    } else {
      this.principal = auth.getName();
    }
  }

  protected IamAuditApplicationEvent(IamEventCategory category, Object source) {
    this(category, source, null);
  }

  public String getPrincipal() {
    return principal;
  }

  public String getMessage() {
    return message;
  }

  public IamEventCategory getCategory() {
    return category;
  }

  @JsonIgnore
  @Override
  public Object getSource() {
    return super.getSource();
  }
  
  @JsonProperty("source")
  public String getSourceClass(){
    return super.getSource().getClass().getSimpleName();
  }
}
