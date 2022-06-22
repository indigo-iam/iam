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
package it.infn.mw.iam.api.common.client;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonValue;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;

public enum AuthorizationGrantType {
  CODE("authorization_code"),
  CLIENT_CREDENTIALS("client_credentials"),
  PASSWORD("password"),
  IMPLICIT("implicit"),
  REFRESH_TOKEN("refresh_token"),
  DEVICE_CODE("urn:ietf:params:oauth:grant-type:device_code"),
  TOKEN_EXCHANGE("urn:ietf:params:oauth:grant-type:token-exchange"),
  REDELEGATE("urn:ietf:params:oauth:grant_type:redelegate");

  private String grantType;

  private static final Map<String, AuthorizationGrantType> reverseLookupTable;

  static {
    reverseLookupTable = new HashMap<>();
    for (AuthorizationGrantType agt : AuthorizationGrantType.values()) {
      reverseLookupTable.put(agt.getGrantType(), agt);
    }
  }

  private AuthorizationGrantType(String grantType) {
    this.grantType = grantType;
  }

  @JsonValue
  public String getGrantType() {
    return grantType;
  }

  public static final AuthorizationGrantType fromGrantType(String grantType) {
    return Optional.ofNullable(reverseLookupTable.get(grantType)).orElseThrow(
        () -> new IllegalArgumentException(
            String.format("%s is not a supported grant type", grantType)));
  }

}
