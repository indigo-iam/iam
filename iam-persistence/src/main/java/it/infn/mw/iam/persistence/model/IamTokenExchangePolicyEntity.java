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
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import javax.persistence.AttributeOverride;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Embedded;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "iam_exchange_policy")
public class IamTokenExchangePolicyEntity implements Serializable {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "description", nullable = true, length = 512)
  private String description;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "creation_time", nullable = false)
  private Date creationTime;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "last_update_time", nullable = false)
  private Date lastUpdateTime;

  @Enumerated(EnumType.STRING)
  @Column(name = "rule", nullable = false, length = 6)
  private PolicyRule rule;

  @Embedded
  @AttributeOverride(name = "type",
      column = @Column(name = "origin_m_type", nullable = false, length = 8))
  @AttributeOverride(name = "matchParam", column = @Column(name = "origin_m_param", length = 256))
  private IamClientMatchingPolicy originClient;


  @Embedded
  @AttributeOverride(name = "type",
      column = @Column(name = "dest_m_type", nullable = false, length = 8))
  @AttributeOverride(name = "matchParam", column = @Column(name = "dest_m_param", length = 256))
  private IamClientMatchingPolicy destinationClient;


  @ElementCollection
  @CollectionTable(name = "iam_exchange_scope_policies",
      joinColumns = @JoinColumn(name = "exchange_policy_id"))
  private Set<IamTokenExchangeScopePolicy> scopePolicies = new HashSet<>();

  private static final long serialVersionUID = 1L;

  public IamTokenExchangePolicyEntity() {
    // must be empty
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
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

  public PolicyRule getRule() {
    return rule;
  }

  public void setRule(PolicyRule rule) {
    this.rule = rule;
  }

  public IamClientMatchingPolicy getOriginClient() {
    return originClient;
  }

  public void setOriginClient(IamClientMatchingPolicy originClient) {
    this.originClient = originClient;
  }

  public IamClientMatchingPolicy getDestinationClient() {
    return destinationClient;
  }

  public void setDestinationClient(IamClientMatchingPolicy destinationClient) {
    this.destinationClient = destinationClient;
  }

  public static long getSerialversionuid() {
    return serialVersionUID;
  }

  @Override
  public int hashCode() {
    return Objects.hash(destinationClient, originClient, rule);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    IamTokenExchangePolicyEntity other = (IamTokenExchangePolicyEntity) obj;
    return Objects.equals(destinationClient, other.destinationClient)
        && Objects.equals(originClient, other.originClient) && rule == other.rule;
  }

  public Set<IamTokenExchangeScopePolicy> getScopePolicies() {
    return scopePolicies;
  }

  public void setScopePolicies(Set<IamTokenExchangeScopePolicy> scopePolicies) {
    this.scopePolicies = scopePolicies;
  }

}
