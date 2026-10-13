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
import java.time.Instant;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "iam_passkey")
public class IamPasskey implements Serializable {

  private static final long serialVersionUID = 1L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "uuid", length = 36, nullable = false, unique = true)
  private String uuid;

  @ManyToOne
  @JoinColumn(name = "account_id", nullable = false)
  private IamAccount account;

  @Column(name = "label", length = 128, nullable = false)
  private String label;

  @Column(name = "credential_id", length = 1400, nullable = false)
  private String credentialId;

  @Column(name = "attested_credential_data", length = 4096, nullable = false)
  private String attestedCredentialData;

  @Column(name = "sign_count", nullable = false)
  private long signCount;

  @Column(name = "aaguid", length = 36)
  private String aaguid;

  @Column(name = "transports", length = 255)
  private String transports;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "creation_time", nullable = false)
  private Date creationTime;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "last_used_time")
  private Date lastUsedTime;

  public IamPasskey() {
    // empty constructor
  }

  public IamPasskey(Instant instant, IamAccount account) {
    this.creationTime = Date.from(instant);
    this.account = account;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getUuid() {
    return uuid;
  }

  public void setUuid(String uuid) {
    this.uuid = uuid;
  }

  public IamAccount getAccount() {
    return account;
  }

  public void setAccount(IamAccount account) {
    this.account = account;
  }

  public String getLabel() {
    return label;
  }

  public void setLabel(String label) {
    this.label = label;
  }

  public String getCredentialId() {
    return credentialId;
  }

  public void setCredentialId(String credentialId) {
    this.credentialId = credentialId;
  }

  public String getAttestedCredentialData() {
    return attestedCredentialData;
  }

  public void setAttestedCredentialData(String attestedCredentialData) {
    this.attestedCredentialData = attestedCredentialData;
  }

  public long getSignCount() {
    return signCount;
  }

  public void setSignCount(long signCount) {
    this.signCount = signCount;
  }

  public String getAaguid() {
    return aaguid;
  }

  public void setAaguid(String aaguid) {
    this.aaguid = aaguid;
  }

  public String getTransports() {
    return transports;
  }

  public void setTransports(String transports) {
    this.transports = transports;
  }

  public Date getCreationTime() {
    return creationTime;
  }

  public void setCreationTime(Date creationTime) {
    this.creationTime = creationTime;
  }

  public Date getLastUsedTime() {
    return lastUsedTime;
  }

  public void setLastUsedTime(Date lastUsedTime) {
    this.lastUsedTime = lastUsedTime;
  }

  public void touchLastUsed(Instant instant) {
    setLastUsedTime(Date.from(instant));
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((credentialId == null) ? 0 : credentialId.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    IamPasskey other = (IamPasskey) obj;
    if (credentialId == null) {
      if (other.credentialId != null)
        return false;
    } else if (!credentialId.equals(other.credentialId))
      return false;
    return true;
  }

  @Override
  public String toString() {
    return "IamPasskey [id=" + id + ", uuid=" + uuid + ", label=" + label + ", signCount="
        + signCount + ", creationTime=" + creationTime + ", lastUsedTime=" + lastUsedTime + "]";
  }
}
