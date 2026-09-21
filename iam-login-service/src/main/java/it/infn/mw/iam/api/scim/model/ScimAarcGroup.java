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

import java.util.Collections;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ScimAarcGroup {

  private final Set<ScimMemberRef> members;

  @JsonCreator
  private ScimAarcGroup(@JsonProperty("members") Set<ScimMemberRef> members) {
    this.members = members != null ? members : Collections.emptySet();
  }

  private ScimAarcGroup(Builder b) {
    this.members = b.members != null ? b.members : Collections.emptySet();
  }

  public Set<ScimMemberRef> getMembers() {
    return members;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    private Set<ScimMemberRef> members = Collections.emptySet();

    public Builder members(Set<ScimMemberRef> members) {
      this.members = members;
      return this;
    }

    public ScimAarcGroup build() {
      return new ScimAarcGroup(this);
    }
  }
}
