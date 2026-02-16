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

import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.MapsId;
import javax.persistence.Table;

@Entity
@Table(name = "authentication_holder_extension")
public class AuthenticationHolderExtension {

  @EmbeddedId
  private AuthenticationExtensionId id = new AuthenticationExtensionId();

  @Column(name = "val", nullable = false)
  private String value;

  @MapsId("ownerId")
  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "owner_id", nullable = false)
  private AuthenticationHolderEntity owner;

  public String getKey() {
    return id.getKey();
  }

  public void setKey(String key) {
    this.id.setKey(key);
  }

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  public AuthenticationHolderEntity getOwner() {
    return owner;
  }

  public void setOwner(AuthenticationHolderEntity owner) {
    this.owner = owner;
  }

  public AuthenticationExtensionId getId() {
    return id;
  }

  public void setId(AuthenticationExtensionId id) {
    this.id = id;
  }

}
