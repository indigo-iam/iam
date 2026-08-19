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
package it.infn.mw.iam.core.userinfo;

import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.SUB;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import it.infn.mw.iam.core.NameUtils;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserInfoResponse {

  public static final String MISSING_SUB_ERROR = "Missing sub key in UserInfoResponse claims";

  private final String sub;
  private final Map<String, Object> additionalFields = new HashMap<>();

  @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
  public UserInfoResponse(Map<String, Object> claims) {

    this.sub = Objects.requireNonNull(claims.get(SUB), MISSING_SUB_ERROR).toString();
    claims.forEach(this::addAdditionalField);
  }

  public String getSub() {
    return sub;
  }

  @JsonIgnore
  public String getGivenName() {
    return getStringOrNull("given_name");
  }

  @JsonIgnore
  public String getFamilyName() {
    return getStringOrNull("family_name");
  }

  @JsonIgnore
  public String getEmail() {
    return getStringOrNull("email");
  }

  @JsonIgnore
  public String getPreferredUsername() {
    return getStringOrNull("preferred_username");
  }

  @JsonIgnore
  public String getName() {
    String givenName = getStringOrNull("given_name");
    String middleName = getStringOrNull("middle_name");
    String familyName = getStringOrNull("family_name");
    return NameUtils.getFormatted(givenName, middleName, familyName);
  }

  private String getStringOrNull(String fieldName) {
    Object obj = additionalFields.get(fieldName);
    return obj != null ? String.valueOf(obj) : null;
  }

  @JsonAnyGetter
  public Map<String, Object> getAdditionalFields() {
    return additionalFields;
  }

  @JsonAnySetter
  public void addAdditionalField(String key, Object value) {
    if (!"sub".equalsIgnoreCase(key)) {
      this.additionalFields.put(key, value);
    }
  }
}
