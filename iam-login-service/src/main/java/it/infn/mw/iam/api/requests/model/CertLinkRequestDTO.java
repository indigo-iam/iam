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
import static eu.emi.security.authn.x509.impl.X500NameUtils.getPortableRFC2253Form;

import it.infn.mw.iam.api.requests.validator.CertLinkRequest;
import it.infn.mw.iam.api.validators.KnownCertificationAuthority;
import it.infn.mw.iam.api.validators.RFC2253Formatted;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@CertLinkRequest
public class CertLinkRequestDTO {

  private String uuid;

  private String username;

  private String userUuid;

  private String userFullName;

  @NotEmpty
  private String label;

  private String pemEncodedCertificate;

  @RFC2253Formatted(message = "Invalid subject DN format")
  private String subjectDn;

  @RFC2253Formatted(message = "Invalid issuer DN format")
  @KnownCertificationAuthority(message = "Certification authority not recognized")
  private String issuerDn;

  private String notes = "";

  private String status;

  private String motivation;

  private Date creationTime;

  private Date lastUpdateTime;

  public CertLinkRequestDTO() {
    // empty constructor
  }

  @JsonCreator
  public CertLinkRequestDTO(@JsonProperty("uuid") String uuid,
      @JsonProperty("userUuid") String userUuid, @JsonProperty("userFullName") String userFullName,
      @JsonProperty("username") String username, @JsonProperty("label") String label,
      @JsonProperty("pemEncodedCertificate") String pemEncodedCertificate,
      @JsonProperty("subjectDn") String subjectDn, @JsonProperty("issuerDn") String issuerDn,
      @JsonProperty("notes") String notes, @JsonProperty("status") String status,
      @JsonProperty("motivation") String motivation,
      @JsonProperty("creation_time") Date creationTime,
      @JsonProperty("last_update_time") Date lastUpdateTime) {

    this.uuid = uuid;
    this.userUuid = userUuid;
    this.username = username;
    this.userFullName = userFullName;
    this.label = label;
    this.pemEncodedCertificate = pemEncodedCertificate;
    this.subjectDn = subjectDn;
    this.issuerDn = issuerDn;
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

  public String getLabel() {
    return label;
  }

  public void setLabel(String label) {
    this.label = label;
  }

  public String getPemEncodedCertificate() {
    return pemEncodedCertificate;
  }

  public void setPemEncodedCertificate(String pemEncodedCertificate) {
    this.pemEncodedCertificate = pemEncodedCertificate;
  }

  public String getSubjectDn() {
    return getPortableRFC2253Form(subjectDn);
  }

  public void setSubjectDn(String subjectDn) {
    this.subjectDn = subjectDn;
  }

  public String getIssuerDn() {
    return getPortableRFC2253Form(issuerDn);
  }

  public void setIssuerDn(String issuerDn) {
    this.issuerDn = issuerDn;
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
