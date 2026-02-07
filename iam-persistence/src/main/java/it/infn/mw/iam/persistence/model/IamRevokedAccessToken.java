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

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "iam_revoked_at")
public class IamRevokedAccessToken {

  @Id
  @Column(name = "hash_value", nullable = false, unique = true, length = 36)
  private String hashValue;

  @Column(name = "expiration")
  private Date expiration;

  @Column(name = "revoked_at", nullable = false)
  private Date revokedAt;

  public String getHashValue() {
    return hashValue;
  }

  public void setHashValue(String hashValue) {
    this.hashValue = hashValue;
  }

  public Date getExpiration() {
    return expiration;
  }

  public void setExpiration(Date expiration) {
    this.expiration = expiration;
  }

  public Date getRevokedAt() {
    return revokedAt;
  }

  public void setRevokedAt(Date revokedAt) {
    this.revokedAt = revokedAt;
  }

}
