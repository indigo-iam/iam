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
package it.infn.mw.iam.core.oauth.model;

import com.fasterxml.jackson.annotation.JsonValue;

public enum OAuth2ErrorCode {

  CONSENT_REQUIRED("consent_required"),

  INVALID_REQUEST("invalid_request"),
  INVALID_CLIENT("invalid_client"),
  INVALID_GRANT("invalid_grant"),
  UNAUTHORIZED_CLIENT("unauthorized_client"),
  UNSUPPORTED_GRANT_TYPE("unsupported_grant_type"),
  INVALID_SCOPE("invalid_scope"),

  ACCESS_DENIED("access_denied"),
  UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),
  SERVER_ERROR("server_error"),
  TEMPORARILY_UNAVAILABLE("temporarily_unavailable"),

  AUTHORIZATION_PENDING("authorization_pending"),
  SLOW_DOWN("slow_down"),
  EXPIRED_TOKEN("expired_token");

  private final String value;

  OAuth2ErrorCode(String value) {
    this.value = value;
  }

  @JsonValue
  public String value() {
    return value;
  }
}
