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
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "iam_account_login_lockout")
public class IamAccountLoginLockout implements Serializable {

  private static final long serialVersionUID = 1L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @OneToOne
  @JoinColumn(name = "account_id", unique = true)
  private IamAccount account;

  @Column(name = "failed_attempts", nullable = false)
  private int failedAttempts;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "first_failure_time")
  private Date firstFailureTime;

  @Column(name = "lockout_count", nullable = false)
  private int lockoutCount;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "suspended_until")
  private Date suspendedUntil;

  public IamAccountLoginLockout() {
    // empty constructor
  }

  public IamAccountLoginLockout(IamAccount account) {
    this.account = account;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public IamAccount getAccount() {
    return account;
  }

  public void setAccount(IamAccount account) {
    this.account = account;
  }

  public int getFailedAttempts() {
    return failedAttempts;
  }

  public void setFailedAttempts(int failedAttempts) {
    this.failedAttempts = failedAttempts;
  }

  public Date getFirstFailureTime() {
    return firstFailureTime;
  }

  public void setFirstFailureTime(Date firstFailureTime) {
    this.firstFailureTime = firstFailureTime;
  }

  public int getLockoutCount() {
    return lockoutCount;
  }

  public void setLockoutCount(int lockoutCount) {
    this.lockoutCount = lockoutCount;
  }

  public Date getSuspendedUntil() {
    return suspendedUntil;
  }

  public void setSuspendedUntil(Date suspendedUntil) {
    this.suspendedUntil = suspendedUntil;
  }

  @Override
  public String toString() {
    return "IamAccountLoginLockout [id=" + id + ", failedAttempts=" + failedAttempts + ", lockoutCount="
        + lockoutCount + ", suspendedUntil=" + suspendedUntil + "]";
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((account == null) ? 0 : account.hashCode());
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
    IamAccountLoginLockout other = (IamAccountLoginLockout) obj;
    if (account == null) {
      if (other.account != null)
        return false;
    } else if (!account.equals(other.account))
      return false;
    return true;
  }
}
