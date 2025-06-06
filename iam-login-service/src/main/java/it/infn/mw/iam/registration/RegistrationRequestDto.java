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

import static it.infn.mw.iam.util.RegexUtil.PASSWORD_REGEX;
import static it.infn.mw.iam.util.RegexUtil.PASSWORD_REGEX_MESSAGE_ERROR;

import java.util.Date;
import java.util.List;

import javax.validation.constraints.Pattern;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonView;
import it.infn.mw.iam.api.client.management.validation.OnRegistrationCreation;
import it.infn.mw.iam.api.common.LabelDTO;
import it.infn.mw.iam.api.common.RegistrationViews;
import it.infn.mw.iam.registration.validation.UsernameRegExp;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonView({RegistrationViews.RegistrationExtendDetail.class,
    RegistrationViews.RegistrationDetail.class})
public class RegistrationRequestDto {

  @JsonView(RegistrationViews.RegistrationExtendDetail.class)
  private String uuid;

  @JsonView(RegistrationViews.RegistrationExtendDetail.class)
  private Date creationTime;

  @JsonView(RegistrationViews.RegistrationExtendDetail.class)
  private String status;

  @JsonView(RegistrationViews.RegistrationExtendDetail.class)
  private Date lastUpdateTime;

  @JsonView({RegistrationViews.RegistrationExtendDetail.class,
      RegistrationViews.RegistrationDetail.class})
  @Size(min = 2, max = 32,
      message = "username cannot be longer than 32 chars and less than 2 chars")
  @UsernameRegExp
  private String username;

  @JsonView(RegistrationViews.RegistrationExtendDetail.class)
  @Pattern(regexp = PASSWORD_REGEX, message = PASSWORD_REGEX_MESSAGE_ERROR,
      groups = {OnRegistrationCreation.class})
  @Size(min = 8, message = "password should have at least 8 characters")
  private String password;

  @JsonView({RegistrationViews.RegistrationExtendDetail.class,
      RegistrationViews.RegistrationDetail.class})
  @Size(min = 2, max = 128, groups = {OnRegistrationCreation.class})
  @NotBlank(message = "givenname cannot be blank")
  private String givenname;

  @JsonView({RegistrationViews.RegistrationExtendDetail.class,
      RegistrationViews.RegistrationDetail.class})
  @Size(min = 2, max = 128, groups = {OnRegistrationCreation.class})
  @NotBlank(message = "familyname cannot be blank")
  private String familyname;

  @JsonView({RegistrationViews.RegistrationExtendDetail.class,
      RegistrationViews.RegistrationDetail.class})
  @Email(message = "must be a valid email address")
  @NotEmpty()
  private String email;

  @JsonView(RegistrationViews.RegistrationExtendDetail.class)
  private String birthdate;

  @JsonView(RegistrationViews.RegistrationExtendDetail.class)
  private String accountId;

  @JsonView({RegistrationViews.RegistrationExtendDetail.class,
      RegistrationViews.RegistrationDetail.class})
  private String notes;

  @JsonView({RegistrationViews.RegistrationExtendDetail.class,
      RegistrationViews.RegistrationDetail.class})
  //@NotBlank(message = "certificate cannot be blank")
  private String certificate;

  @JsonView({RegistrationViews.RegistrationExtendDetail.class,
    RegistrationViews.RegistrationDetail.class})
//@NotBlank(message = "certificate cannot be blank")
private String subjectdn;

@JsonView({RegistrationViews.RegistrationExtendDetail.class,
  RegistrationViews.RegistrationDetail.class})
//@NotBlank(message = "certificate cannot be blank")
private String issuerdn;

  @JsonView({RegistrationViews.RegistrationExtendDetail.class,
      RegistrationViews.RegistrationDetail.class})
  private List<LabelDTO> labels;

  public RegistrationRequestDto() {}

  @JsonCreator
  public RegistrationRequestDto(@JsonProperty(value = "username", required = true) String username,
      @JsonProperty(value = "givenname", required = true) String givenname,
      @JsonProperty(value = "familyname", required = true) String familyname,
      @JsonProperty(value = "email", required = true) String email,
      @JsonProperty("notes") String notes, @JsonProperty("password") String password,
      @JsonProperty("uuid") String uuid, @JsonProperty("birthdate") String birthdate,
      @JsonProperty("accountId") String accountId, @JsonProperty("creationTime") Date creationTime,
      @JsonProperty("status") String status, @JsonProperty("lastUpdateTime") Date lastUpdateTime,
      @JsonProperty("labels") List<LabelDTO> labels) {
    super();
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

  public List<LabelDTO> getLabels() {
    return labels;
  }

  public void setLabels(List<LabelDTO> labels) {
    this.labels = labels;
  }
}
