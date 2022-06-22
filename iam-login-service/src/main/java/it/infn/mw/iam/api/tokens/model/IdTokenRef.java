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
package it.infn.mw.iam.api.tokens.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class IdTokenRef {

  private Long id;
  private String ref;

  @JsonCreator
  public IdTokenRef(@JsonProperty("id") Long id, @JsonProperty("$ref") String ref) {

    this.id = id;
    this.ref = ref;
  }

  public IdTokenRef(Builder builder) {

    this.id = builder.id;
    this.ref = builder.ref;
  }

  @JsonProperty("id")
  public Long getId() {

    return id;
  }

  @JsonProperty("$ref")
  public String getRef() {

    return ref;
  }

  @Override
  public String toString() {
    return "IdToken [id=" + id + ", ref=" + ref + "]";
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private Long id;
    private String ref;

    public Builder id(Long id) {
      this.id = id;
      return this;
    }

    public Builder ref(String ref) {
      this.ref = ref;
      return this;
    }

    public IdTokenRef build() {
      return new IdTokenRef(this);
    }
  }
}

