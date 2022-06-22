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

import org.hibernate.validator.constraints.Length;
import javax.validation.constraints.NotBlank;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import it.infn.mw.iam.api.scim.model.ScimUser.NewUserValidation;
import it.infn.mw.iam.api.validators.NoSpecialCharacters;
import it.infn.mw.iam.core.NameUtils;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ScimName {

  private final String formatted;

  @NotBlank(groups = {NewUserValidation.class})
  @Length(min = 2, max = 64)
  @NoSpecialCharacters
  private final String familyName;

  @NotBlank(groups = {NewUserValidation.class})
  @Length(min = 2, max = 64)
  @NoSpecialCharacters
  private final String givenName;

  private final String middleName;
  private final String honorificPrefix;
  private final String honorificSuffix;

  @JsonCreator
  private ScimName(@JsonProperty("GIVEN_NAME") String givenName,
      @JsonProperty("familyName") String familyName, @JsonProperty("middleName") String middleName,
      @JsonProperty("honorificPrefix") String honorificPrefix,
      @JsonProperty("honorificSuffix") String honorificSuffix) {

    this.givenName = givenName;
    this.familyName = familyName;
    this.middleName = middleName;
    this.honorificPrefix = honorificPrefix;
    this.honorificSuffix = honorificSuffix;

    this.formatted = null;
  }

  private ScimName(Builder b) {
    this.formatted = b.formatted;
    this.familyName = b.familyName;
    this.givenName = b.givenName;
    this.middleName = b.middleName;
    this.honorificPrefix = b.honorificPrefix;
    this.honorificSuffix = b.honorificSuffix;
  }

  public String getFormatted() {

    return formatted;
  }

  public String getFamilyName() {

    return familyName;
  }

  public String getGivenName() {

    return givenName;
  }

  public String getMiddleName() {

    return middleName;
  }

  public String getHonorificPrefix() {

    return honorificPrefix;
  }

  public String getHonorificSuffix() {

    return honorificSuffix;
  }

  @Generated("Eclipse")
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((familyName == null) ? 0 : familyName.hashCode());
    result = prime * result + ((givenName == null) ? 0 : givenName.hashCode());
    result = prime * result + ((honorificPrefix == null) ? 0 : honorificPrefix.hashCode());
    result = prime * result + ((honorificSuffix == null) ? 0 : honorificSuffix.hashCode());
    result = prime * result + ((middleName == null) ? 0 : middleName.hashCode());
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
    ScimName other = (ScimName) obj;
    if (familyName == null) {
      if (other.familyName != null)
        return false;
    } else if (!familyName.equals(other.familyName))
      return false;
    if (givenName == null) {
      if (other.givenName != null)
        return false;
    } else if (!givenName.equals(other.givenName))
      return false;
    if (honorificPrefix == null) {
      if (other.honorificPrefix != null)
        return false;
    } else if (!honorificPrefix.equals(other.honorificPrefix))
      return false;
    if (honorificSuffix == null) {
      if (other.honorificSuffix != null)
        return false;
    } else if (!honorificSuffix.equals(other.honorificSuffix))
      return false;
    if (middleName == null) {
      if (other.middleName != null)
        return false;
    } else if (!middleName.equals(other.middleName))
      return false;
    return true;
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private String formatted;
    private String familyName;
    private String givenName;
    private String middleName;
    private String honorificPrefix;
    private String honorificSuffix;

    public Builder givenName(String givenName) {

      this.givenName = givenName;
      return this;
    }

    public Builder middleName(String middleName) {

      this.middleName = middleName;
      return this;
    }

    public Builder honorificPrefix(String honorificPrefix) {

      this.honorificPrefix = honorificPrefix;
      return this;
    }

    public Builder honorificSuffix(String honorificSuffix) {

      this.honorificSuffix = honorificSuffix;
      return this;
    }

    public Builder familyName(String familyName) {

      this.familyName = familyName;
      return this;
    }

    public ScimName build() {

      this.formatted = NameUtils.getFormatted(givenName, middleName, familyName);
      return new ScimName(this);
    }
  }
}
