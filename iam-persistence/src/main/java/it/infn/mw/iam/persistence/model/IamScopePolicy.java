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


import static it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy.EQ;

import java.io.Serializable;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.annotation.Generated;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

@Entity
@Table(name = "iam_scope_policy")
public class IamScopePolicy implements Serializable {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public enum PolicyType {
    DEFAULT,
    ACCOUNT,
    GROUP
  }

  public enum MatchingPolicy {
    EQ,
    REGEXP,
    PATH
  }

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

  @ManyToOne(optional = true)
  @JoinColumn(name = "group_id")
  private IamGroup group;

  @ManyToOne(optional = true)
  @JoinColumn(name = "account_id")
  private IamAccount account;

  @ElementCollection
  @Column(name = "scope", length = 256)
  @CollectionTable(name = "iam_scope_policy_scope", joinColumns = @JoinColumn(name = "policy_id"),
      indexes = {@Index(columnList = "policy_id,scope", unique = true),
          @Index(columnList = "scope", unique = false)})
  private Set<String> scopes = new HashSet<>();

  @Enumerated(EnumType.STRING)
  @Column(name = "matching_policy", nullable = false, length = 6)
  private MatchingPolicy matchingPolicy = EQ;

  public IamScopePolicy() {
    // empty constructor
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

  public IamGroup getGroup() {
    return group;
  }

  public void setGroup(IamGroup group) {
    this.group = group;
  }


  public Set<String> getScopes() {
    return scopes;
  }

  public void setScopes(Set<String> scopes) {
    this.scopes = scopes;
  }

  public IamAccount getAccount() {
    return account;
  }

  public void setAccount(IamAccount account) {
    this.account = account;
  }

  public void linkAccount() {
    if (account != null) {
      account.getScopePolicies().add(this);
    }
  }

  public void linkGroup() {
    if (group != null) {
      group.getScopePolicies().add(this);
    }
  }

  public void linkAccount(IamAccount account) {
    setAccount(account);
    account.getScopePolicies().add(this);
  }

  public void linkGroup(IamGroup group) {
    setGroup(group);
    group.getScopePolicies().add(this);
  }

  @Transient
  public boolean isPermit() {
    return PolicyRule.PERMIT.equals(rule);
  }

  @Transient
  public PolicyType getPolicyType() {
    if (getGroup() == null && getAccount() == null) {
      return PolicyType.DEFAULT;
    }

    if (getGroup() != null) {
      return PolicyType.GROUP;
    }

    return PolicyType.ACCOUNT;

  }


  public void from(IamScopePolicy other) {
    setAccount(other.getAccount());
    setGroup(other.getGroup());
    setDescription(other.getDescription());
    setRule(other.getRule());
    setScopes(other.getScopes());
    linkAccount();
    linkGroup();
  }

  @Override
  @Generated("eclipse")
  public int hashCode() {
    int prime = 31;
    int result = 1;
    result = prime * result + ((account == null) ? 0 : account.hashCode());
    result = prime * result + ((group == null) ? 0 : group.hashCode());
    result = prime * result + ((id == null) ? 0 : id.hashCode());
    result = prime * result + ((rule == null) ? 0 : rule.hashCode());
    result = prime * result + ((scopes == null) ? 0 : scopes.hashCode());
    return result;
  }

  public MatchingPolicy getMatchingPolicy() {
    return matchingPolicy;
  }

  public void setMatchingPolicy(MatchingPolicy matchingPolicy) {
    this.matchingPolicy = matchingPolicy;
  }

  @Override
  @Generated("eclipse")
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    IamScopePolicy other = (IamScopePolicy) obj;
    if (account == null) {
      if (other.account != null)
        return false;
    } else if (!account.equals(other.account))
      return false;
    if (group == null) {
      if (other.group != null)
        return false;
    } else if (!group.equals(other.group))
      return false;
    if (id == null) {
      if (other.id != null)
        return false;
    } else if (!id.equals(other.id))
      return false;
    if (rule != other.rule)
      return false;
    if (scopes == null) {
      if (other.scopes != null)
        return false;
    } else if (!scopes.equals(other.scopes))
      return false;
    return true;
  }

  @Override
  public String toString() {
    return "IamScopePolicy [id=" + id + ", description=" + description + ", creationTime="
        + creationTime + ", lastUpdateTime=" + lastUpdateTime + ", rule=" + rule + ", group="
        + group + ", account=" + account + ", scopes=" + scopes + ", matchingPolicy="
        + matchingPolicy + "]";
  }
}
