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
import com.fasterxml.jackson.annotation.JsonProperty;

import it.infn.mw.iam.api.validators.KnownCertificationAuthority;
import it.infn.mw.iam.api.validators.RFC2253Formatted;
import it.infn.mw.iam.api.validators.ValidCertificateDTO;
import it.infn.mw.iam.api.validators.PemContent;

@ValidCertificateDTO
public class CertLinkRequestDTO extends IamRequestDTO implements CertificateDTO {

  @NotEmpty
  private String label;

  @PemContent(message = "Invalid PEM encoded certificate")
  private String pemEncodedCertificate;

  @RFC2253Formatted(message = "Invalid subject DN format")
  private String subjectDn;

  @RFC2253Formatted(message = "Invalid issuer DN format")
  @KnownCertificationAuthority(message = "Certification authority not recognized")
  private String issuerDn;

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

    super(uuid, userUuid, userFullName, username, notes, status, motivation, creationTime, lastUpdateTime);
    this.label = label;
    this.pemEncodedCertificate = pemEncodedCertificate;
    this.subjectDn = subjectDn;
    this.issuerDn = issuerDn;
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
    return subjectDn;
  }

  public void setSubjectDn(String subjectDn) {
    this.subjectDn = subjectDn;
  }

  public String getIssuerDn() {
    return issuerDn;
  }

  public void setIssuerDn(String issuerDn) {
    this.issuerDn = issuerDn;
  }

}
