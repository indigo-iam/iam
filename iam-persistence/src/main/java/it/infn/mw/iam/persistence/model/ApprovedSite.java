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
import java.util.Set;

import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

@Entity
@Table(name = "approved_site")
public class ApprovedSite implements Serializable {

  private static final long serialVersionUID = 1L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  @ManyToOne
  @JoinColumn(name = "user_id", referencedColumnName = "username")
  private IamAccount account;

  @ManyToOne
  @JoinColumn(name = "client_id", referencedColumnName = "client_id")
  private ClientDetailsEntity client;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "creation_date")
  private Date creationDate;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "access_date")
  private Date accessDate;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "timeout_date")
  private Date timeoutDate;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "approved_site_scope", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "scope")
  private Set<String> allowedScopes;

  public ApprovedSite() {

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

  public ClientDetailsEntity getClient() {
    return client;
  }

  public void setClient(ClientDetailsEntity client) {
    this.client = client;
  }

  public Date getCreationDate() {
    return creationDate;
  }

  public void setCreationDate(Date creationDate) {
    this.creationDate = creationDate;
  }

  public Date getAccessDate() {
    return accessDate;
  }

  public void setAccessDate(Date accessDate) {
    this.accessDate = accessDate;
  }

  public Set<String> getAllowedScopes() {
    return allowedScopes;
  }

  public void setAllowedScopes(Set<String> allowedScopes) {
    this.allowedScopes = allowedScopes;
  }

  public Date getTimeoutDate() {
    return timeoutDate;
  }

  public void setTimeoutDate(Date timeoutDate) {
    this.timeoutDate = timeoutDate;
  }

  @Transient
  public boolean isExpired() {
    if (timeoutDate != null) {
      return timeoutDate.before(new Date());
    }
    return false;
  }

}

