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

import com.fasterxml.jackson.annotation.JsonValue;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;

public enum OAuthResponseType {

  CODE("code"),
  TOKEN("token");

  private String responseType;

  private OAuthResponseType(String responseType) {
    this.responseType = responseType;
  }

  @JsonValue
  public String getResponseType() {
    return responseType;
  }

  public static final OAuthResponseType fromResponseType(String value) {
    if (value.equals("code")) {
      return CODE;
    } else if (value.equals("token")) {
      return TOKEN;
    } else
      throw new IllegalArgumentException(String.format("Usupported response type: %s", value));
  }
}
