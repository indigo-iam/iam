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
import java.time.Clock;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import com.google.common.base.Preconditions;

@Entity
@Table(name = "iam_group")
public class IamGroup implements Serializable {

  private static final long serialVersionUID = 1L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 36, unique = true)
  private String uuid;

  @Column(nullable = false, length = 512, unique = true)
  private String name;

  @Column(nullable = true, length = 512)
  private String description;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "creationtime", nullable = false)
  Date creationTime;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "lastupdatetime", nullable = false)
  Date lastUpdateTime;

  @Column(name = "default_group", nullable = false)
  boolean defaultGroup;

  @ManyToOne
  @JoinColumn(name = "parent_group_id", nullable = true)
  private IamGroup parentGroup;

  @OneToMany(mappedBy = "parentGroup", cascade = CascadeType.PERSIST)
  private Set<IamGroup> childrenGroups = new HashSet<>();

  @OneToMany(mappedBy = "group", cascade = CascadeType.REMOVE)
  private Set<IamScopePolicy> scopePolicies = new HashSet<>();

  @OneToMany(mappedBy = "group", cascade = CascadeType.REMOVE)
  private Set<IamGroupRequest> groupRequests = new HashSet<>();

  @ElementCollection
  @CollectionTable(indexes = {@Index(columnList = "name"), @Index(columnList = "name,val")},
      name = "iam_group_attrs", joinColumns = @JoinColumn(name = "group_id"))
  private Set<IamAttribute> attributes = new HashSet<>();

  @ElementCollection
  @CollectionTable(
      indexes = {@Index(columnList = "prefix,name,val"), @Index(columnList = "prefix,name")},
      name = "iam_group_labels", joinColumns = @JoinColumn(name = "group_id"))
  private Set<IamLabel> labels = new HashSet<>();

  public IamGroup() {
    // empty constructor
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getUuid() {
    return uuid;
  }

  public void setUuid(String uuid) {

    this.uuid = uuid;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
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

  public IamGroup getParentGroup() {
    return parentGroup;
  }

  public void setParentGroup(IamGroup parentGroup) {
    this.parentGroup = parentGroup;
  }

  public Set<IamGroup> getChildrenGroups() {
    return childrenGroups;
  }

  public void setChildrenGroups(Set<IamGroup> childrenGroups) {
    this.childrenGroups = childrenGroups;
  }

  public Set<IamScopePolicy> getScopePolicies() {
    return scopePolicies;
  }

  public void setScopePolicies(Set<IamScopePolicy> scopePolicies) {
    this.scopePolicies = scopePolicies;
  }

  public Set<IamGroupRequest> getGroupRequests() {
    return groupRequests;
  }

  public void setGroupRequests(Set<IamGroupRequest> groupRequests) {
    this.groupRequests = groupRequests;
  }

  public boolean isDefaultGroup() {
    return defaultGroup;
  }

  public boolean isSubgroupOf(IamGroup otherGroup) {
    Preconditions.checkNotNull(otherGroup, "Cannot check subgroup status of a null group");

    if (this.equals(otherGroup)) {
      return false;
    }
    
    IamGroup aParentGroup = this.getParentGroup();

    while (aParentGroup != null) {
      if (aParentGroup.equals(otherGroup)) {
        return true;
      } else {
        aParentGroup = aParentGroup.getParentGroup();
      }
    }

    return false;
  }

  public void setDefaultGroup(boolean defaultGroup) {
    this.defaultGroup = defaultGroup;
  }

  public Set<IamAttribute> getAttributes() {
    return attributes;
  }

  public void setAttributes(Set<IamAttribute> attributes) {
    this.attributes = attributes;
  }

  public Set<IamLabel> getLabels() {
    return labels;
  }

  public void setLabels(Set<IamLabel> labels) {
    this.labels = labels;
  }

  public void touch(Clock c) {
    setLastUpdateTime(Date.from(c.instant()));
  }


  @Override
  public int hashCode() {

    final int prime = 31;
    int result = 1;
    result = prime * result + ((uuid == null) ? 0 : uuid.hashCode());
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
    IamGroup other = (IamGroup) obj;
    if (uuid == null) {
      if (other.uuid != null)
        return false;
    } else if (!uuid.equals(other.uuid))
      return false;
    return true;
  }

  @Override
  public String toString() {
    return String.format(
        "IamGroup [id=%s, uuid=%s, name=%s, description=%s, creationTime=%s, lastUpdateTime=%s]",
        id, uuid, name, description, creationTime, lastUpdateTime);
  }
}
