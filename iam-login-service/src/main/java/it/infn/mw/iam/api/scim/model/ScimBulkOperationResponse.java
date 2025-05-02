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

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonInclude(Include.NON_EMPTY)
public class ScimBulkOperationResponse {
  @NotNull
  private final String method;

  @NotNull
  private final String status;

  //Only for Success response (any)
  private final String location;

  //Only for Success response (POST only)
  private final String bulkId;

  //Only for Error response
  private final ScimErrorResponse errorResponse;

  @JsonCreator
  public ScimBulkOperationResponse(@JsonProperty("method") String method, 
    @JsonProperty("status") String status, @JsonProperty("location") String location,
    @JsonProperty("bulkId") String bulkId, @JsonProperty("errorResponse") ScimErrorResponse errorResponse) {
    this.method = method;
    this.status = status;
    this.location = location;
    this.bulkId = bulkId;
    this.errorResponse = errorResponse;
  }

  public ScimBulkOperationResponse(Builder builder) {
    this.method = builder.method;
    this.location = builder.location;
    this.status = builder.status; 
    this.bulkId = builder.bulkId;
    this.errorResponse = builder.errorResponse;
  }

  public String getMethod() {

    return method;
  }
  
  public String getLocation() {

    return location;
  }

  public String getStatus() {

    return status;
  }

  public String getbulkId() {

    return bulkId;
  }

  public ScimErrorResponse getErrorResponse() {

    return errorResponse;
  }

  public static class Builder {

    String method;
    String location;
    String status;
    String bulkId;
    ScimErrorResponse errorResponse;

    public Builder location(String location) {

      this.location = location;
      return this;
    }

    public Builder method(String method) {

      this.method = method;
      return this;
    }

    public Builder status(String status) {

        this.status = status;
        return this;
      }

    public Builder bulkId(String bulkId) {

        this.bulkId = bulkId;
        return this;
      }

    public Builder errorResponse(ScimErrorResponse errorResponse) {

        this.errorResponse = errorResponse;
        return this;
      }

    public ScimBulkOperationResponse build() {

      return new ScimBulkOperationResponse(this);
    }
  }

}