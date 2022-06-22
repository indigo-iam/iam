/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

  public enum IamEventCategory {
    NONE,
    ACCOUNT,
    GROUP,
    REGISTRATION,
    AUTHENTICATION,
    AUTHORIZATION,
    SCOPE_POLICY,
    AUP,
    MEMBERSHIP,
    CLIENT
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
