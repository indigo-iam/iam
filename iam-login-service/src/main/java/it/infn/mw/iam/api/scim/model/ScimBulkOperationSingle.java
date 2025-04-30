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

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

public class ScimBulkOperationSingle {
  @NotNull
  private final String method;

  @NotNull
  private final String path;

  @NotNull
  private final JsonNode data;

  private final String bulkId;

  @JsonCreator
  public ScimBulkOperationSingle(@JsonProperty("method") String method,
      @JsonProperty("path") String path, @JsonProperty("data") JsonNode data) {
    this.method = method;
    this.path = path;
    this.data = data; 
    this.bulkId = null;
  }

  public ScimBulkOperationSingle(Builder builder) {
    this.method = builder.method;
    this.path = builder.path;
    this.data = builder.data; 
    this.bulkId = builder.bulkId;
  }

  public String getMethod() {

    return method;
  }
  
  public String getPath() {

    return path;
  }

  public JsonNode getData() {

    return data;
  }

  public String getbulkId() {

    return bulkId;
  }
  public static Builder operationBuilder() {

    return new Builder();
  }

  public <T> T getDataAs(Class<T> type, ObjectMapper mapper) throws JsonProcessingException{
    return mapper.treeToValue(data, type);
  }

  public static class Builder {

    String method;
    String path;
    JsonNode data;
    String bulkId;

    public Builder path(String path) {

      this.path = path;
      return this;
    }

    public Builder method(String method) {

      this.method = method;
      return this;
    }

    public Builder data(JsonNode data) {

        this.data = data;
        return this;
      }

    public Builder bulkId(String bulkId) {

        this.bulkId = bulkId;
        return this;
      }

    public ScimBulkOperationSingle build() {

      return new ScimBulkOperationSingle(this);
    }
  }

}