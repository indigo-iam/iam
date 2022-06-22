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
package it.infn.mw.iam.authn.oidc.model;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.Maps;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class TokenEndpointErrorResponse {

  String error;

  @JsonProperty("error_description")
  String errorDescription;

  @JsonProperty("error_uri")
  String errorUri;

  @JsonIgnore
  Map<String, Object> unknownFields = Maps.newHashMap();

  public TokenEndpointErrorResponse() {}

  @JsonCreator
  public TokenEndpointErrorResponse(@JsonProperty("error") String error,
      @JsonProperty("error_description") String errorDescription,
      @JsonProperty("error_uri") String errorUri) {

    this.error = error;
    this.errorDescription = errorDescription;
    this.errorUri = errorUri;
  }

  public String getError() {
    return error;
  }

  public void setError(String error) {
    this.error = error;
  }

  public String getErrorDescription() {
    return errorDescription;
  }

  public void setErrorDescription(String errorDescription) {
    this.errorDescription = errorDescription;
  }

  public String getErrorUri() {
    return errorUri;
  }

  public void setErrorUri(String errorUri) {
    this.errorUri = errorUri;
  }

  @JsonAnySetter
  public void handleUnkwownFields(String key, Object value) {
    unknownFields.put(key, value);
  }

}
