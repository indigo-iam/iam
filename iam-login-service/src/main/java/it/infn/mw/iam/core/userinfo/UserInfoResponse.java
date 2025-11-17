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

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserInfoResponse {

  private String sub;

  private final Map<String, Object> additionalFields = new HashMap<>();

  public UserInfoResponse(Map<String, Object> claims) {

    if (!claims.containsKey(SUB)) {
      throw new IllegalArgumentException("Missing sub key in UserInfoResponse claims");
    }
    setSub(String.valueOf(claims.get(SUB)));
    claims.forEach(this::addAdditionalField);
  }

  public String getSub() {
    return sub;
  }

  public void setSub(String sub) {
    this.sub = sub;
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
