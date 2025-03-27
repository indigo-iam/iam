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
package it.infn.mw.iam.core.oauth.introspection.model;

import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class IntrospectionResponse {

  private boolean active;

  private final Map<String, Object> additionalFields = new HashMap<>();

  public IntrospectionResponse() {
    // Required for de-serialization
  }

  private IntrospectionResponse(Builder builder) {
    this.active = builder.active;
    this.additionalFields.putAll(builder.additionalFields);
  }

  public boolean isActive() {
    return active;
  }

  public void setActive(boolean active) {
    this.active = active;
  }

  @JsonAnyGetter
  public Map<String, Object> getAdditionalFields() {
      return additionalFields;
  }

  @JsonAnySetter
  public void addAdditionalField(String key, Object value) {
    this.additionalFields.put(key, value);
  }

  public static IntrospectionResponse inactive() {
    return new IntrospectionResponse.Builder(false).build();
  }

  public static class Builder {

    private final boolean active;
    private final Map<String, Object> additionalFields = new HashMap<>();

    public Builder(boolean active) {
      this.active = active;
    }

    public Builder addField(String key, Object value) {
      this.additionalFields.put(key, value);
      return this;
    }

    public IntrospectionResponse build() {
      return new IntrospectionResponse(this);
    }
  }
}
