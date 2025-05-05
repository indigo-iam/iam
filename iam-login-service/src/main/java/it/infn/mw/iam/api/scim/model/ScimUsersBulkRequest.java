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
import javax.validation.Valid;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

@JsonInclude(Include.NON_EMPTY)
public class ScimUsersBulkRequest {

  public static final String BULKREQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
  @NotEmpty
  private final Set<String> schemas;
  @NotEmpty
  @Valid
  private final List<ScimBulkOperationSingle> operations;

  private long failOnErrors;

  @JsonCreator
  private ScimUsersBulkRequest(@JsonProperty("schemas") Set<String> schemas,
      @JsonProperty("operations") List<ScimBulkOperationSingle> operations, 
      @JsonProperty("failOnErrors") long failOnErrors) {

    this.schemas = schemas;
    this.operations = operations;
    this.failOnErrors = (failOnErrors != 0 ? failOnErrors : -1); 
  }

  private ScimUsersBulkRequest(Builder b) {
    this.failOnErrors = b.failOnErrors;
    this.schemas = b.schemas;
    this.operations = b.operations;
  }

  public Set<String> getSchemas() {

    return schemas;
  }

  public List<ScimBulkOperationSingle> getOperations() {

    return operations;
  }

  public long getfailOnErrors() {

    return failOnErrors;
  }

  public void decrementfailOnError(){
    if (failOnErrors > 0){
      failOnErrors--;
    }
  }

  public static Builder requestBuilder() {

    return new Builder();
  }

  public static Builder requestBuilder(long failOnErrors) {

    return new Builder(failOnErrors);
  }

  public static class Builder {

    private Set<String> schemas = new HashSet<>();
    private List<ScimBulkOperationSingle> operations = new ArrayList<>();
    private long failOnErrors = -1; 

    public Builder() {
      schemas.add(BULKREQUEST_SCHEMA);
    }

    public Builder(long maxErrors) {
      schemas.add(BULKREQUEST_SCHEMA);
      failOnErrors = maxErrors;
    }

    public Builder addPostSingleOperation(JsonNode postBody, String bulkId, String path) {

      operations.add(( new ScimBulkOperationSingle.Builder()).method("POST")
        .path(path)
        .bulkId(bulkId)
        .data(postBody)
        .build());
      return this;
    }

    public Builder addPatchSingleOperation(JsonNode patchBody, String path) {

      operations.add(( new ScimBulkOperationSingle.Builder()).method("PATCH")
        .path(path)
        .data(patchBody)
        .build());
      return this;
    }

    public ScimUsersBulkRequest build() {

      return new ScimUsersBulkRequest(this);
    }
  }
}
