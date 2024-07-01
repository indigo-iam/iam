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
package it.infn.mw.iam.registration;

import java.util.Date;
import java.util.List;

import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import it.infn.mw.iam.api.common.LabelDTO;
import it.infn.mw.iam.registration.validation.UsernameRegExp;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class RegistrationRequestDto {

  private String uuid;
  private Date creationTime;
  private String status;
  private Date lastUpdateTime;
  @Size(max = 32, message = "username cannot be longer than 32 chars")
  @UsernameRegExp
  private String username;
  private String password;
  private String givenname;
  private String familyname;
  private String email;
  private String birthdate;
  private String accountId;
  private String notes;
  private String affiliation;

  private List<LabelDTO> labels;

  public RegistrationRequestDto() {}

  @JsonCreator
  public RegistrationRequestDto(@JsonProperty("uuid") String uuid,
      @JsonProperty("creationdate") Date creationTime, @JsonProperty("status") String status,
      @JsonProperty("lastupdatetime") Date lastUpdateTime,
      @JsonProperty("username") String username, @JsonProperty("password") String password,
      @JsonProperty("givename") String givenname, @JsonProperty("familyname") String familyname,
      @JsonProperty("email") String email, @JsonProperty("birthdate") String birthdate,
      @JsonProperty("accountid") String accountId, @JsonProperty("notes") String notes,
      @JsonProperty("affiliation") String affiliation, @JsonProperty("labels") List<LabelDTO> labels) {

    this.username = username;
    this.password = password;
    this.givenname = givenname;
    this.familyname = familyname;
    this.email = email;
    this.birthdate = birthdate;
    this.uuid = uuid;
    this.creationTime = creationTime;
    this.status = status;
    this.lastUpdateTime = lastUpdateTime;
    this.accountId = accountId;
    this.notes = notes;
    this.affiliation = affiliation;
    this.labels = labels;
  }

  public String getUuid() {

    return uuid;
  }

  public void setUuid(String uuid) {

    this.uuid = uuid;
  }

  public Date getCreationTime() {

    return creationTime;
  }

  public void setCreationTime(Date creationTime) {

    this.creationTime = creationTime;
  }

  public String getStatus() {

    return status;
  }

  public void setStatus(String status) {

    this.status = status;
  }

  public Date getLastUpdateTime() {

    return lastUpdateTime;
  }

  public void setLastUpdateTime(Date lastUpdateTime) {

    this.lastUpdateTime = lastUpdateTime;
  }

  public String getUsername() {

    return username;
  }

  public void setUsername(String username) {

    this.username = username;
  }

  public String getPassword() {

    return password;
  }

  public void setPassword(String password) {

    this.password = password;
  }

  public String getGivenname() {

    return givenname;
  }

  public void setGivenname(String givenname) {

    this.givenname = givenname;
  }

  public String getFamilyname() {

    return familyname;
  }

  public void setFamilyname(String familyname) {

    this.familyname = familyname;
  }

  public String getEmail() {

    return email;
  }

  public void setEmail(String email) {

    this.email = email;
  }

  public String getBirthdate() {

    return birthdate;
  }

  public void setBirthdate(String birthdate) {

    this.birthdate = birthdate;
  }

  public String getAccountId() {

    return accountId;
  }

  public void setAccountId(String accountId) {

    this.accountId = accountId;
  }

  public String getNotes() {
    return notes;
  }

  public void setNotes(String notes) {
    this.notes = notes;
  }

  public String getAffiliation() {
    return affiliation;
  }

  public void setAffiliation(String affiliation) {
    this.affiliation = affiliation;
  }

  public List<LabelDTO> getLabels() {
    return labels;
  }

  public void setLabels(List<LabelDTO> labels) {
    this.labels = labels;
  }
}
