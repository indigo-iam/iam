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
package it.infn.mw.iam.api.account.group_manager.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import it.infn.mw.iam.api.common.GroupDTO;

public class AccountManagedGroupsDTO {

  final String id;
  final String username;
  
  final List<GroupDTO> managedGroups;
  final List<GroupDTO> unmanagedGroups;

  private AccountManagedGroupsDTO(Builder builder) {
    this.id = builder.id;
    this.username = builder.username;
    this.managedGroups = Collections.unmodifiableList(builder.managedGroups);
    this.unmanagedGroups = Collections.unmodifiableList(builder.unmanagedGroups);
  }
  
  public String getId() {
    return id;
  }
  
  
  public String getUsername() {
    return username;
  }

  public List<GroupDTO> getManagedGroups() {
    return managedGroups;
  }


  public List<GroupDTO> getUnmanagedGroups() {
    return unmanagedGroups;
  }


  public static class Builder {
    String username;
    String id;
    List<GroupDTO> managedGroups = new ArrayList<>();
    List<GroupDTO> unmanagedGroups = new ArrayList<>();

    public Builder() {
      // empty constructor
    }

    public Builder username(String username) {
      this.username = username;
      return this;
    }

    public Builder id(String id) {
      this.id = id;
      return this;
    }

    public Builder managedGroups(List<GroupDTO> managedGroups) {
      this.managedGroups = managedGroups;
      return this;
    }

    public Builder unmanagedGroups(List<GroupDTO> unmanagedGroups) {
      this.unmanagedGroups = unmanagedGroups;
      return this;
    }

    public AccountManagedGroupsDTO build() {
      return new AccountManagedGroupsDTO(this);
    }
  }
  
  public static Builder builder() {
    return new Builder();
  }
}
