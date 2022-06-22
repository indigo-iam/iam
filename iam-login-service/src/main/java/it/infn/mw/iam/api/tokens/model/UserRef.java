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
public class UserRef {

  private String id;
  private String userName;
  private String ref;

  @JsonCreator
  public UserRef(@JsonProperty("id") String id, @JsonProperty("userName") String userName,
      @JsonProperty("$ref") String ref) {

    this.id = id;
    this.userName = userName;
    this.ref = ref;
  }

  public UserRef(Builder builder) {

    this.id = builder.id;
    this.userName = builder.userName;
    this.ref = builder.ref;
  }

  @JsonProperty("id")
  public String getId() {
    return id;
  }

  @JsonProperty("userName")
  public String getUserName() {
    return userName;
  }

  @JsonProperty("$ref")
  public String getRef() {
    return ref;
  }

  @Override
  public String toString() {
    return "User [id=" + id + ", userName=" + userName + ", ref=" + ref + "]";
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private String id;
    private String userName;
    private String ref;

    public Builder id(String id) {
      this.id = id;
      return this;
    }

    public Builder userName(String userName) {
      this.userName = userName;
      return this;
    }

    public Builder ref(String ref) {
      this.ref = ref;
      return this;
    }

    public UserRef build() {
      return new UserRef(this);
    }
  }
}
