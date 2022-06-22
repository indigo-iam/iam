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
package it.infn.mw.iam.api.common;

import javax.validation.Valid;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import javax.validation.groups.Default;

import com.fasterxml.jackson.annotation.JsonProperty;

import it.infn.mw.iam.api.common.GroupDTO.CreateGroup;
import it.infn.mw.iam.api.group.validator.GroupNameAssigned;
import it.infn.mw.iam.api.group.validator.ValidGroupName;
import it.infn.mw.iam.api.scope_policy.GroupRefDTO;

@ValidGroupName(groups=CreateGroup.class)
public class GroupDTO {
  
  public static final String NAME_REGEXP = "^[a-zA-Z][a-zA-Z0-9\\-_.]*$";

  public interface UpdateGroup extends Default {
  }
  
  public interface CreateGroup extends UpdateGroup {
    
  }

  @Size(max=512, message="name cannot be longer than 512 chars", groups=CreateGroup.class)
  @GroupNameAssigned(message="name is already assigned", groups=CreateGroup.class)
  @Pattern(regexp = NAME_REGEXP,
      message = "invalid name (does not match with regexp: '" + NAME_REGEXP + "')",
      groups = CreateGroup.class)
  final String name;
  
  @Size(max=512, message="description cannot be longer than 512 chars", groups= {UpdateGroup.class})
  final String description;
  
  final String id;
  
  @Valid
  final GroupRefDTO parent;

  private GroupDTO(Builder builder) {
    this.name = builder.name;
    this.id = builder.id;
    this.description = builder.description;
    this.parent = builder.parent;
  }

  public GroupDTO(@JsonProperty("name") String name, @JsonProperty("id") String id, @JsonProperty("description") String description, @JsonProperty("parent") GroupRefDTO parent) {
    this.name = name;
    this.id = id;
    this.description = description;
    this.parent = parent;
  }

  public String getName() {
    return name;
  }

  public String getId() {
    return id;
  }
  
  public String getDescription() {
    return description;
  }
  
  public GroupRefDTO getParent() {
    return parent;
  }
  
  public static class Builder {
    String name;
    String id;
    String description;
    
    GroupRefDTO parent;

    public Builder() {
      // empty constructor
    }

    public Builder id(String id) {
      this.id = id;
      return this;
    }

    public Builder name(String name) {
      this.name = name;
      return this;
    }
    
    public Builder description(String desc) {
      this.description = desc;
      return this;
    }
    
    public Builder parent(GroupRefDTO parent) {
      this.parent = parent;
      return this;
    }

    public GroupDTO build() {
      return new GroupDTO(this);
    }
  }

  public static Builder builder() {
    return new Builder();
  }

}
