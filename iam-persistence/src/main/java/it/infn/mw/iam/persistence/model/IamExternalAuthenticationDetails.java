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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "iam_ext_authn")
public class IamExternalAuthenticationDetails implements Serializable{

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  Long id;

  @Column(name = "saved_authn_id", updatable = false, unique = true)
  Long savedAuthenticationId;

  @Column(name = "type", length = 32, nullable = false)
  String type;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(nullable = false, name = "authentication_time")
  Date authenticationTime;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(nullable = false, name = "expiration_time")
  Date expirationTime;

  @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true, mappedBy = "details")
  List<IamExternalAuthenticationAttribute> attributes = new ArrayList<>();

  public IamExternalAuthenticationDetails() {
    // empty on purpose
  }

  public void addAttribute(String name, String value) {
    IamExternalAuthenticationAttribute attr = new IamExternalAuthenticationAttribute();
    attr.setName(name);
    attr.setValue(value);
    attr.setDetails(this);
    attributes.add(attr);
  }

  public List<IamExternalAuthenticationAttribute> getAttributes() {
    return attributes;
  }

  public Date getAuthenticationTime() {
    return authenticationTime;
  }

  public Date getExpirationTime() {
    return expirationTime;
  }

  public Long getId() {
    return id;
  }

  public Long getSavedAuthenticationId() {
    return savedAuthenticationId;
  }


  public String getType() {
    return type;
  }

  public void setAttributes(List<IamExternalAuthenticationAttribute> attributes) {
    this.attributes = attributes;
  }



  public void setAuthenticationTime(Date authenticationTime) {
    this.authenticationTime = authenticationTime;
  }



  public void setExpirationTime(Date expirationTime) {
    this.expirationTime = expirationTime;
  }



  public void setId(Long id) {
    this.id = id;
  }



  public void setSavedAuthenticationId(Long savedAuthenticationId) {
    this.savedAuthenticationId = savedAuthenticationId;
  }



  public void setType(String type) {
    this.type = type;
  }

}
