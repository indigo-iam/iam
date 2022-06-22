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

import javax.annotation.Generated;

import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ScimOidcId {

  @NotEmpty
  private final String issuer;
  @NotEmpty
  private final String subject;

  @JsonCreator
  private ScimOidcId(@JsonProperty("issuer") String issuer,
      @JsonProperty("subject") String subject) {

    this.issuer = issuer;
    this.subject = subject;
  }

  private ScimOidcId(Builder b) {
    this.issuer = b.issuer;
    this.subject = b.subject;
  }

  public String getIssuer() {

    return issuer;
  }

  public String getSubject() {

    return subject;
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private String issuer;
    private String subject;

    public Builder issuer(String issuer) {

      this.issuer = issuer;
      return this;
    }

    public Builder subject(String subject) {

      this.subject = subject;
      return this;
    }

    public ScimOidcId build() {

      return new ScimOidcId(this);
    }
  }

  @Generated("Eclipse")
  @Override
  public int hashCode() {
    int prime = 31;
    int result = 1;
    result = prime * result + ((issuer == null) ? 0 : issuer.hashCode());
    result = prime * result + ((subject == null) ? 0 : subject.hashCode());
    return result;
  }

  @Generated("Eclipse")
  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    ScimOidcId other = (ScimOidcId) obj;
    if (issuer == null) {
      if (other.issuer != null)
        return false;
    } else if (!issuer.equals(other.issuer))
      return false;
    if (subject == null) {
      if (other.subject != null)
        return false;
    } else if (!subject.equals(other.subject))
      return false;
    return true;
  }

  @Override
  public String toString() {
    return "ScimOidcId [issuer=" + issuer + ", subject=" + subject + "]";
  }
}
