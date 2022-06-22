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

import javax.validation.Valid;

import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Preconditions;

@JsonInclude(Include.NON_EMPTY)
public class ScimUserPatchRequest {

  public static final String PATCHOP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

  private final Set<String> schemas;

  @NotEmpty
  @Valid
  private final List<ScimPatchOperation<ScimUser>> operations;

  @JsonCreator
  private ScimUserPatchRequest(@JsonProperty("schemas") Set<String> schemas,
      @JsonProperty("operations") List<ScimPatchOperation<ScimUser>> operations) {

	Preconditions.checkNotNull(operations, "Operation list is null");
    this.schemas = schemas;
    this.operations = operations;
  }

  private ScimUserPatchRequest(Builder b) {

    this.schemas = b.schemas;
    this.operations = b.operations;
  }

  public Set<String> getSchemas() {

    return schemas;
  }

  public List<ScimPatchOperation<ScimUser>> getOperations() {

    return operations;
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private Set<String> schemas = new HashSet<>();
    private List<ScimPatchOperation<ScimUser>> operations =
        new ArrayList<>();

    public Builder() {
      schemas.add(PATCHOP_SCHEMA);
    }

    public Builder add(ScimUser user) {

      operations.add((new ScimPatchOperation.Builder<ScimUser>()).add().value(user).build());
      return this;
    }

    public Builder remove(ScimUser user) {

      operations.add((new ScimPatchOperation.Builder<ScimUser>()).remove().value(user).build());
      return this;
    }

    public Builder replace(ScimUser user) {

      operations.add((new ScimPatchOperation.Builder<ScimUser>()).replace().value(user).build());
      return this;
    }

    public ScimUserPatchRequest build() {

      return new ScimUserPatchRequest(this);
    }
  }

}
