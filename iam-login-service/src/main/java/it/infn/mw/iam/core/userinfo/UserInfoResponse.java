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
package it.infn.mw.iam.core.userinfo;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserInfoResponse {

  private String sub;

  private final Map<String, Object> additionalFields = new HashMap<>();

  public UserInfoResponse() {
    // Required for de-serialization
  }

  private UserInfoResponse(Builder builder) {
    this.sub = builder.sub;
    this.additionalFields.putAll(builder.additionalFields);
  }

  public String getSub() {
    return sub;
  }

  public void setSub(String sub) {
    this.sub = sub;
  }

  @JsonAnyGetter
  public Map<String, Object> getAdditionalFields() {
    return additionalFields;
  }

  @JsonAnySetter
  public void addAdditionalField(String key, Object value) {
    this.additionalFields.put(key, value);
  }

  public static class Builder {

    private final String sub;
    private final Map<String, Object> additionalFields = new HashMap<>();

    public Builder(String sub) {
      this.sub = sub;
    }

    public Builder addField(String key, Object value) {
      this.additionalFields.put(key, value);
      return this;
    }

    public Builder addFieldsFromJson(JsonObject json, List<String> excluded) {

      ObjectMapper jacksonMapper = new ObjectMapper();
      json.keySet()
        .stream()
        .filter(key -> !excluded.contains(key))
        .filter(key -> isValidField(json.get(key)))
        .forEach(key -> {
          try {
            this.additionalFields.put(key,
                jacksonMapper.readValue(json.get(key).toString(), Object.class));
          } catch (Exception e) {
            // Skip on exception
          }
        });
      return this;
    }

    private boolean isValidField(JsonElement element) {
      if (element.isJsonNull()) {
        return false;
      }
      if (element.isJsonPrimitive() && element.getAsString().isBlank()) {
        return false;
      }
      if (element.isJsonArray() && element.getAsJsonArray().size() == 0) {
        return false;
      }
      return true;
    }

    public UserInfoResponse build() {
      return new UserInfoResponse(this);
    }
  }
}
