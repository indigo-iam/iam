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
package it.infn.mw.iam.core.oidc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class FederationError {

  private final String error;
  @JsonProperty("error_description")
  private final String errorDescription;

  @JsonCreator
  public FederationError(String error, @JsonProperty("error_description") String errorDescription) {
    this.error = error;
    this.errorDescription = errorDescription;
  }

  public String getError() {
    return error;
  }

  public String getErrorDescription() {
    return errorDescription;
  }
}
