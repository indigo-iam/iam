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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public abstract class IamRequestDTO {

    private String uuid;

    private String username;

    private String userUuid;

    private String userFullName;

    private String notes = "";

    private String status;

    private String motivation;

    private Date creationTime;

    private Date lastUpdateTime;

    protected IamRequestDTO() {
        // empty constructor
    }

    @JsonCreator
    protected IamRequestDTO(@JsonProperty("uuid") String uuid,
            @JsonProperty("userUuid") String userUuid,
            @JsonProperty("userFullName") String userFullName,
            @JsonProperty("username") String username, @JsonProperty("notes") String notes,
            @JsonProperty("status") String status, @JsonProperty("motivation") String motivation,
            @JsonProperty("creation_time") Date creationTime,
            @JsonProperty("last_update_time") Date lastUpdateTime) {

        this.uuid = uuid;
        this.userUuid = userUuid;
        this.username = username;
        this.userFullName = userFullName;
        this.notes = notes;
        this.status = status;
        this.motivation = motivation;
        this.creationTime = creationTime;
        this.lastUpdateTime = lastUpdateTime;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getMotivation() {
        return motivation;
    }

    public void setMotivation(String motivation) {
        this.motivation = motivation;
    }

    public Date getCreationTime() {
        return creationTime;
    }

    public void setCreationTime(Date creationTime) {
        this.creationTime = creationTime;
    }

    public Date getLastUpdateTime() {
        return lastUpdateTime;
    }

    public void setLastUpdateTime(Date lastUpdateTime) {
        this.lastUpdateTime = lastUpdateTime;
    }

    public String getUserUuid() {
        return userUuid;
    }

    public void setUserUuid(String userUuid) {
        this.userUuid = userUuid;
    }

    public String getUserFullName() {
        return userFullName;
    }

    public void setUserFullName(String userFullName) {
        this.userFullName = userFullName;
    }

}
