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

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Entity
@Table(name = "iam_totp_admin_key")
public class IamTotpAdminKey implements Serializable {

  private static final long serialVersionUID = 1L;

  @Id
  private Long id = 1L;

  // Stores the hash of the admin MFA key
  @Column(name = "admin_mfa_key_hash", nullable = false)
  private String adminMfaKeyHash;

  // Last time the key was updated
  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "last_update_time", nullable = false)
  private Date lastUpdateTime;

  public IamTotpAdminKey() {}

  public IamTotpAdminKey(String adminMfaKeyHash) {
    this.id = 1L;
    this.adminMfaKeyHash = adminMfaKeyHash;
  }

  @PrePersist
  protected void onCreate() {
    this.lastUpdateTime = new Date();
  }

  @PreUpdate
  protected void onUpdate() {
    this.lastUpdateTime = new Date();
  }

  // Getters and setters
  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getAdminMfaKeyHash() {
    return adminMfaKeyHash;
  }

  public void setAdminMfaKeyHash(String adminMfaKeyHash) {
    this.adminMfaKeyHash = adminMfaKeyHash;
  }

  public Date getLastUpdateTime() {
    return lastUpdateTime;
  }

  public void setLastUpdateTime(Date lastUpdateTime) {
    this.lastUpdateTime = lastUpdateTime;
  }

  @Override
  public String toString() {
    return "IamTotpAdminKey [id=" + id + ", lastUpdateTime=" + lastUpdateTime + "]";
  }

  @Override
  public int hashCode() {
   final int prime = 31;
   int result = 1;
   result = prime * result + ((id == null) ? 0 : id.hashCode());

   return result;
 }
  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null || getClass() != obj.getClass()) return false;
    IamTotpAdminKey other = (IamTotpAdminKey) obj;
    return id != null && id.equals(other.id);
  }
}
