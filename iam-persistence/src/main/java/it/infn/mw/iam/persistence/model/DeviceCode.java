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
import java.util.Map;
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
import javax.persistence.MapKeyColumn;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "device_code")
public class DeviceCode implements Serializable {

  private static final long serialVersionUID = 1L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  @Column(name = "device_code")
  private String deviceCode;

  @Column(name = "user_code")
  private String userCode;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "device_code_scope", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "scope")
  private Set<String> scope;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "expiration")
  private Date expiration;

  @ManyToOne
  @JoinColumn(name = "client_id", referencedColumnName = "client_id")
  private ClientDetailsEntity client;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "device_code_request_parameter",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "val")
  @MapKeyColumn(name = "param")
  private Map<String, String> requestParameters;

  @Column(name = "approved")
  private boolean approved;

  @ManyToOne
  @JoinColumn(name = "auth_holder_id")
  private AuthenticationHolderEntity authenticationHolder;

  public DeviceCode() {

  }

  public DeviceCode(String deviceCode, String userCode, Set<String> scope,
      ClientDetailsEntity client, Map<String, String> params) {
    this.deviceCode = deviceCode;
    this.userCode = userCode;
    this.scope = scope;
    this.client = client;
    this.requestParameters = params;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getDeviceCode() {
    return deviceCode;
  }

  public void setDeviceCode(String deviceCode) {
    this.deviceCode = deviceCode;
  }

  public String getUserCode() {
    return userCode;
  }

  public void setUserCode(String userCode) {
    this.userCode = userCode;
  }


  public Set<String> getScope() {
    return scope;
  }

  public void setScope(Set<String> scope) {
    this.scope = scope;
  }

  public Date getExpiration() {
    return expiration;
  }

  public void setExpiration(Date expiration) {
    this.expiration = expiration;
  }

  public ClientDetailsEntity getClient() {
    return client;
  }

  public void setClient(ClientDetailsEntity client) {
    this.client = client;
  }

  public Map<String, String> getRequestParameters() {
    return requestParameters;
  }

  public void setRequestParameters(Map<String, String> params) {
    this.requestParameters = params;
  }

  public boolean isApproved() {
    return approved;
  }

  public void setApproved(boolean approved) {
    this.approved = approved;
  }

  public AuthenticationHolderEntity getAuthenticationHolder() {
    return authenticationHolder;
  }

  public void setAuthenticationHolder(AuthenticationHolderEntity authenticationHolder) {
    this.authenticationHolder = authenticationHolder;
  }

}
