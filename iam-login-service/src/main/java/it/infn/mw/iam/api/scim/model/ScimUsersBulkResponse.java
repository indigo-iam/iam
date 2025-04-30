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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(Include.NON_EMPTY)
public class ScimUsersBulkResponse {

  public static final String BULKREQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
  @NotEmpty
  private final Set<String> schemas;
  private final List<ScimBulkOperationResponse> operations;

  @JsonCreator
  private ScimUsersBulkResponse(@JsonProperty("schemas") Set<String> schemas,
      @JsonProperty("operations") List<ScimBulkOperationResponse> operations) {

    this.schemas = schemas;
    this.operations = operations;
  }

  private ScimUsersBulkResponse(Builder b) {

    this.schemas = b.schemas;
    this.operations = b.operations;
  }

  public Set<String> getSchemas() {

    return schemas;
  }

  public List<ScimBulkOperationResponse> getOperations() {

    return operations;
  }

  public static Builder reponseBuilder() {

    return new Builder();
  }

  public static class Builder {

    private Set<String> schemas = new HashSet<>();
    private List<ScimBulkOperationResponse> operations = new ArrayList<>();;

    public Builder() {
      schemas.add(BULKREQUEST_SCHEMA);
    }

    public Builder addSuccessResponse(String method, String location, String status) {

      operations.add((new ScimBulkOperationResponse.Builder()).method(method)
        .location(location)
        .status(status)
        .build());
      return this;
    }

    public Builder addSuccessResponse(String method, String location, String bulkId, String status) {

      operations.add((new ScimBulkOperationResponse.Builder()).method(method)
        .location(location)
        .bulkId(bulkId)
        .status(status)
        .build());
      return this;
    }

    public Builder addErrorResponse(String method, String status, ScimErrorResponse response) {

      operations.add((new ScimBulkOperationResponse.Builder()).method(method)
        .errorResponse(response)
        .status(status)
        .build());
      return this;
    }

    public Builder addErrorResponse(String method, String bulkId, String status, ScimErrorResponse response) {

      operations.add((new ScimBulkOperationResponse.Builder()).method(method)
        .errorResponse(response)
        .bulkId(bulkId)
        .status(status)
        .build());
      return this;
    }

    public ScimUsersBulkResponse build() {

      return new ScimUsersBulkResponse(this);
    }
  }
}