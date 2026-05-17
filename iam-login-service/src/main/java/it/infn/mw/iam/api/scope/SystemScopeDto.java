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
package it.infn.mw.iam.api.scope;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SystemScopeDto {

  @JsonProperty(access = JsonProperty.Access.READ_ONLY)
  private Long id;

  private String value;

  private String description;

  private String icon;

  private boolean defaultScope;

  private boolean restricted;

  public SystemScopeDto() {}

  private SystemScopeDto(Builder builder) {
    this.id = builder.id;
    this.value = builder.value;
    this.description = builder.description;
    this.icon = builder.icon;
    this.defaultScope = builder.defaultScope;
    this.restricted = builder.restricted;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public String getIcon() {
    return icon;
  }

  public void setIcon(String icon) {
    this.icon = icon;
  }

  public boolean isDefaultScope() {
    return defaultScope;
  }

  public void setDefaultScope(boolean defaultScope) {
    this.defaultScope = defaultScope;
  }

  public boolean isRestricted() {
    return restricted;
  }

  public void setRestricted(boolean restricted) {
    this.restricted = restricted;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    private Long id;
    private String value;
    private String description;
    private String icon;
    private boolean defaultScope;
    private boolean restricted;

    public Builder id(Long id) {
      this.id = id;
      return this;
    }

    public Builder value(String value) {
      this.value = value;
      return this;
    }

    public Builder description(String description) {
      this.description = description;
      return this;
    }

    public Builder icon(String icon) {
      this.icon = icon;
      return this;
    }

    public Builder defaultScope(boolean defaultScope) {
      this.defaultScope = defaultScope;
      return this;
    }

    public Builder restricted(boolean restricted) {
      this.restricted = restricted;
      return this;
    }

    public SystemScopeDto build() {
      return new SystemScopeDto(this);
    }
  }
}
