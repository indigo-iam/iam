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
import java.time.LocalDate;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.MapsId;
import javax.persistence.OneToOne;
import javax.persistence.Table;

@Entity
@Table(name = "client_last_used")
public class ClientLastUsedEntity implements Serializable {

  private static final long serialVersionUID = 1L;

  @Id
  @Column(name = "client_details_id")
  private Long id;

  @OneToOne(cascade = CascadeType.ALL)
  @MapsId
  @JoinColumn(name = "client_details_id")
  private ClientDetailsEntity client;

  @Column(name = "last_used", nullable = false)
  private LocalDate lastUsed;

  public ClientLastUsedEntity() {
    // empty constructor
  }

  public ClientLastUsedEntity(ClientDetailsEntity client, LocalDate lastUsed) {
    this.client = client;
    this.lastUsed = lastUsed;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public ClientDetailsEntity getClient() {
    return client;
  }

  public void setClient(ClientDetailsEntity client) {
    this.client = client;
  }

  public LocalDate getLastUsed() {
    return lastUsed;
  }

  public void setLastUsed(LocalDate lastUsed) {
    this.lastUsed = lastUsed;
  }
}
