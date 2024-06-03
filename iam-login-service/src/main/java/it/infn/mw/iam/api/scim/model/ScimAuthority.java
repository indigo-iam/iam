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
package it.infn.mw.iam.api.scim.model;

import java.util.Objects;

import javax.validation.constraints.NotEmpty;

import org.hibernate.validator.constraints.Length;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ScimAuthority {

  @NotEmpty
  @Length(max = 128)
  private String authority;

  @JsonCreator
  private ScimAuthority(@JsonProperty("authority") String authority) {
    this.authority = authority;
  }

  public String getAuthority() {
    return authority;
  }

  public void setAuthority(String authority) {
    this.authority = authority;
  }

  @Override
  public int hashCode() {
    return Objects.hash(authority);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    ScimAuthority other = (ScimAuthority) obj;
    return Objects.equals(authority, other.authority);
  }

  private ScimAuthority(Builder builder) {
    this.authority = builder.authority;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private String authority;

    public Builder withAuthority(String authority) {
      this.authority = authority;
      return this;
    }

    public ScimAuthority build() {
      return new ScimAuthority(this);
    }
  }
}
