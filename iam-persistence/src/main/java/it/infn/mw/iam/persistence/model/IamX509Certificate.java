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

import static java.util.Objects.isNull;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.Lob;
import javax.persistence.ManyToOne;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "iam_x509_cert")
public class IamX509Certificate implements IamAccountRef, Serializable {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 36)
  private String label;

  @Column(name = "subject_dn", nullable = false, length = 128, unique = true)
  private String subjectDn;

  @Column(name = "issuer_dn", nullable = false, length = 128)
  private String issuerDn;

  @Lob
  @Column(nullable = true, unique = true)
  private String certificate;

  @Column(name = "is_primary")
  private boolean primary;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "creation_time", nullable = false)
  Date creationTime;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "last_update_time", nullable = false)
  Date lastUpdateTime;

  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "account_id")
  private IamAccount account;

  @OneToOne(optional = true, cascade = CascadeType.ALL, orphanRemoval=true)
  @JoinColumn(name = "proxy_id")
  private IamX509ProxyCertificate proxy;

  public IamX509Certificate() {
    // empty on purpose
  }


  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((subjectDn == null) ? 0 : subjectDn.hashCode());
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
    IamX509Certificate other = (IamX509Certificate) obj;
    if (subjectDn == null) {
      if (other.subjectDn != null)
        return false;
    } else if (!subjectDn.equals(other.subjectDn))
      return false;
    return true;
  }

  @Override
  public IamAccount getAccount() {

    return account;
  }

  public String getSubjectDn() {

    return subjectDn;
  }

  public String getCertificate() {

    return certificate;
  }

  public Long getId() {

    return id;
  }

  public String getLabel() {

    return label;
  }

  public boolean isPrimary() {

    return primary;
  }

  @Override
  public void setAccount(IamAccount account) {

    this.account = account;
  }

  public void setSubjectDn(String certificateSubject) {

    this.subjectDn = certificateSubject;
  }

  public void setCertificate(String certificate) {

    this.certificate = certificate;
  }

  public void setId(Long id) {

    this.id = id;
  }

  public void setLabel(String label) {

    this.label = label;
  }

  public void setPrimary(boolean primary) {

    this.primary = primary;
  }

  public String getIssuerDn() {
    return issuerDn;
  }

  public void setIssuerDn(String issuerDn) {
    this.issuerDn = issuerDn;
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


  public IamX509ProxyCertificate getProxy() {
    return proxy;
  }


  public void setProxy(IamX509ProxyCertificate proxy) {
    this.proxy = proxy;
  }


  public boolean hasProxy() {
    return !isNull(getProxy());
  }
  @Override
  public String toString() {
    return "IamX509Certificate [label=" + label + ", subjectDn=" + subjectDn + ", issuerDn="
        + issuerDn + ", certificate=" + certificate + ", primary=" + primary + ", creationTime="
        + creationTime + ", lastUpdateTime=" + lastUpdateTime + "]";
  }
}
