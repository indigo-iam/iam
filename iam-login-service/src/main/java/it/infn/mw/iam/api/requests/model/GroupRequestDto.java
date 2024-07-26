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
package it.infn.mw.iam.api.requests.model;

import java.util.Date;

import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import it.infn.mw.iam.api.requests.validator.GroupRequest;
import it.infn.mw.iam.api.validators.IamGroupName;
import it.infn.mw.iam.api.validators.IamGroupRequestNotes;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@GroupRequest
public class GroupRequestDto extends IamRequestDTO {

  @NotEmpty
  @IamGroupName(message = "Invalid membership request: group does not exist")
  private String groupName;

  private String groupUuid;

  @NotEmpty
  @IamGroupRequestNotes(message = "Invalid membership request: notes cannot be empty")
  private String notes;

  public GroupRequestDto() {
    // empty constructor
  }

  @JsonCreator
  public GroupRequestDto(@JsonProperty("uuid") String uuid,
      @JsonProperty("userUuid") String userUuid, @JsonProperty("userFullName") String userFullName,
      @JsonProperty("username") String username, @JsonProperty("group_name") String groupName,
      @JsonProperty("group_uuid") String groupUuid, @JsonProperty("status") String status,
      @JsonProperty("notes") String notes, @JsonProperty("motivation") String motivation,
      @JsonProperty("creation_time") Date creationTime,
      @JsonProperty("last_update_time") Date lastUpdateTime) {

    super(uuid, userUuid, userFullName, username, notes, status, motivation, creationTime,
        lastUpdateTime);
    this.groupName = groupName;
    this.groupUuid = groupUuid;
    this.notes = notes;
  }

  public String getGroupName() {
    return groupName;
  }

  public void setGroupName(String groupName) {
    this.groupName = groupName;
  }

  @Override
  public String getNotes() {
    return notes;
  }

  @Override
  public void setNotes(String notes) {
    this.notes = notes;
  }

  public String getGroupUuid() {
    return groupUuid;
  }

  public void setGroupUuid(String groupUuid) {
    this.groupUuid = groupUuid;
  }
}
