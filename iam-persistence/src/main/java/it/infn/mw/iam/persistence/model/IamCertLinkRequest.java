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
package it.infn.mw.iam.persistence.model;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.CascadeType;

import it.infn.mw.iam.core.IamRequestStatus;

@Entity
@Table(name = "iam_cert_link_request")
public class IamCertLinkRequest implements Serializable {

  private static final long serialVersionUID = 1L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 36, unique = true)
  private String uuid;

  @OneToOne
  @JoinColumn(name = "account_id")
  private IamAccount account;

  @OneToOne(cascade = CascadeType.PERSIST)
  @JoinColumn(name = "iam_x509_cert_id")
  private IamX509Certificate certificate;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 50)
  private IamRequestStatus status;

  @Column(nullable = false)
  private String notes;

  @Column(nullable = true)
  private String motivation;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "creationtime", nullable = false)
  private Date creationTime;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "lastupdatetime", nullable = true)
  private Date lastUpdateTime;

  public IamCertLinkRequest() {
    // empty constructor
  }

  public Long getId() {
    return id;
  }

  public void setId(final Long id) {
    this.id = id;
  }

  public String getUuid() {
    return uuid;
  }

  public void setUuid(final String uuid) {
    this.uuid = uuid;
  }

  public IamAccount getAccount() {
    return account;
  }

  public void setAccount(final IamAccount account) {
    this.account = account;
  }

  public IamX509Certificate getCertificate() {
    return certificate;
  }

  public void setCertificate(IamX509Certificate certificate) {
    this.certificate = certificate;
  }

  public void setStatus(IamRequestStatus status) {
    this.status = status;
  }

  public String getNotes() {
    return notes;
  }

  public void setNotes(String notes) {
    this.notes = notes;
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

  public void setCreationTime(final Date creationTime) {
    this.creationTime = creationTime;
  }

  public IamRequestStatus getStatus() {
    return status;
  }

  public Date getLastUpdateTime() {
    return lastUpdateTime;
  }

  public void setLastUpdateTime(final Date lastUpdateTime) {
    this.lastUpdateTime = lastUpdateTime;
  }

  @Override
  public int hashCode() {

    final int prime = 31;
    int result = 1;
    result = prime * result + ((id == null) ? 0 : id.hashCode());
    return result;
  }

  @Override
  public boolean equals(final Object obj) {

    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    IamCertLinkRequest other = (IamCertLinkRequest) obj;

    if (id == null) {
      if (other.id != null)
        return false;
    } else if (!id.equals(other.id)) {
      return false;
    }
    return true;
  }

  @Override
  public String toString() {
    return String.format(
        "IamCertLinkRequest [id=%s, uuid=%s, accountUsername=%s, certificateName=%s, subject=%s, issuer=%s, status=%s,creationTime=%s, lastUpdateTime=%s]",
        id, uuid, account.getUsername(), certificate.getLabel(), certificate.getSubjectDn(), certificate.getIssuerDn(),
        status, creationTime, lastUpdateTime);
  }
}
