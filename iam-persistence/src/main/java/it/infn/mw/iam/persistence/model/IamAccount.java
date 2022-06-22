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

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.Serializable;
import java.time.Clock;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;

import com.google.common.base.Preconditions;

@Entity
@Table(name = "iam_account")
public class IamAccount implements Serializable {

  private static final long serialVersionUID = 1L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 36, unique = true)
  private String uuid;

  @Column(nullable = false, length = 128, unique = true)
  @NotNull
  private String username;

  @Column(length = 128)
  private String password;

  @Column(name = "active", nullable = false)
  private boolean active;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "creationtime", nullable = false)
  private Date creationTime;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "lastupdatetime", nullable = false)
  private Date lastUpdateTime;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "end_time", nullable = true)
  private Date endTime;

  @Column(name = "provisioned", nullable = false)
  private boolean provisioned = false;

  @OneToOne(cascade = CascadeType.ALL)
  @JoinColumn(name = "user_info_id")
  private IamUserInfo userInfo;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "last_login_time", nullable = true)
  private Date lastLoginTime;

  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(name = "iam_account_authority",
      joinColumns = @JoinColumn(name = "account_id", referencedColumnName = "id"),
      inverseJoinColumns = @JoinColumn(name = "authority_id", referencedColumnName = "id"))
  private Set<IamAuthority> authorities = new HashSet<>();

  @OneToMany(mappedBy = "account", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<IamAccountGroupMembership> groups = new HashSet<>();

  @OneToMany(mappedBy = "account", cascade = CascadeType.ALL, fetch = FetchType.EAGER,
      orphanRemoval = true)
  private Set<IamSamlId> samlIds = new HashSet<>();

  @OneToMany(mappedBy = "account", cascade = CascadeType.ALL, fetch = FetchType.EAGER,
      orphanRemoval = true)
  private Set<IamOidcId> oidcIds = new HashSet<>();

  @OneToMany(mappedBy = "account", cascade = CascadeType.ALL, fetch = FetchType.EAGER,
      orphanRemoval = true)
  private Set<IamSshKey> sshKeys = new LinkedHashSet<>();

  @OneToMany(mappedBy = "account", cascade = CascadeType.ALL, fetch = FetchType.EAGER,
      orphanRemoval = true)
  private Set<IamX509Certificate> x509Certificates = new HashSet<>();

  @Column(name = "confirmation_key", unique = true, length = 36)
  private String confirmationKey;

  @Column(name = "reset_key", unique = true, length = 36)
  private String resetKey;

  @OneToOne(mappedBy = "account", cascade = CascadeType.REMOVE)
  private IamRegistrationRequest registrationRequest;

  @OneToMany(mappedBy = "account", cascade = CascadeType.REMOVE)
  private Set<IamScopePolicy> scopePolicies = new HashSet<>();

  @OneToOne(cascade = CascadeType.REMOVE, mappedBy = "account")
  private IamAupSignature aupSignature;

  @OneToMany(mappedBy = "account", cascade = CascadeType.REMOVE)
  private Set<IamGroupRequest> groupRequests = new HashSet<>();

  @ElementCollection
  @CollectionTable(indexes = {@Index(columnList = "name"), @Index(columnList = "name,val")},
      name = "iam_account_attrs", joinColumns = @JoinColumn(name = "account_id"))
  private Set<IamAttribute> attributes = new HashSet<>();

  @ElementCollection
  @CollectionTable(
      indexes = {@Index(columnList = "prefix,name,val"), @Index(columnList = "prefix,name")},
      name = "iam_account_labels", joinColumns = @JoinColumn(name = "account_id"))
  private Set<IamLabel> labels = new HashSet<>();

  public IamAccount() {
    // empty constructor
  }

  public Long getId() {

    return id;
  }

  public void setId(final Long id) {

    this.id = id;
  }

  public String getUuid() {

    return uuid;
  }

  public void setUuid(final String uuid) {

    this.uuid = uuid;
  }

  public String getUsername() {

    return username;
  }

  public void setUsername(final String username) {

    this.username = username;
  }

  public String getPassword() {

    return password;
  }

  public void setPassword(final String password) {

    this.password = password;
  }

  public IamUserInfo getUserInfo() {

    return userInfo;
  }

  public void setUserInfo(final IamUserInfo userInfo) {

    this.userInfo = userInfo;
  }

  public Set<IamAuthority> getAuthorities() {

    return authorities;
  }

  public void setAuthorities(final Set<IamAuthority> authorities) {

    this.authorities = authorities;
  }


  public Date getCreationTime() {

    return creationTime;
  }

  public void setCreationTime(final Date creationTime) {

    this.creationTime = creationTime;
  }

  public Date getLastUpdateTime() {

    return lastUpdateTime;
  }

  public void setLastUpdateTime(final Date lastUpdateTime) {

    this.lastUpdateTime = lastUpdateTime;
  }

  public boolean isActive() {

    return active;
  }

  public void setActive(final boolean active) {

    this.active = active;
  }

  public Set<IamSamlId> getSamlIds() {

    return samlIds;
  }

  public void setSamlIds(Set<IamSamlId> samlIds) {

    Preconditions.checkNotNull(samlIds);
    this.samlIds = samlIds;
  }

  public Set<IamOidcId> getOidcIds() {

    return oidcIds;
  }

  public void setOidcIds(Set<IamOidcId> oidcIds) {

    Preconditions.checkNotNull(oidcIds);
    this.oidcIds = oidcIds;
  }

  public Set<IamSshKey> getSshKeys() {

    return sshKeys;
  }

  public void setSshKeys(Set<IamSshKey> sshKeys) {

    Preconditions.checkNotNull(sshKeys);
    this.sshKeys = sshKeys;
  }

  public Set<IamX509Certificate> getX509Certificates() {

    return x509Certificates;
  }

  public void setX509Certificates(Set<IamX509Certificate> x509Certificates) {

    Preconditions.checkNotNull(x509Certificates);
    this.x509Certificates = x509Certificates;
  }

  public boolean hasX509Certificates() {

    return !x509Certificates.isEmpty();
  }

  public boolean hasOidcIds() {

    return !oidcIds.isEmpty();
  }

  public boolean hasSshKeys() {

    return !sshKeys.isEmpty();
  }

  public boolean hasSamlIds() {

    return !samlIds.isEmpty();
  }

  public boolean hasPicture() {

    return userInfo.getPicture() != null && !userInfo.getPicture().isEmpty();
  }

  public void linkOidcIds(Collection<IamOidcId> ids) {

    checkNotNull(ids);
    for (IamOidcId oidcId : ids) {
      link(oidcIds, oidcId, this);
    }
  }

  public void unlinkOidcIds(Collection<IamOidcId> ids) {

    checkNotNull(ids);
    for (IamOidcId oidcId : ids) {
      unlink(oidcIds.iterator(), oidcId);
    }
  }

  public void linkSamlIds(Collection<IamSamlId> ids) {

    checkNotNull(ids);
    for (IamSamlId samlId : ids) {
      link(samlIds, samlId, this);
    }
  }

  public void unlinkSamlIds(Collection<IamSamlId> ids) {

    checkNotNull(ids);
    for (IamSamlId samlId : ids) {
      unlink(samlIds.iterator(), samlId);
    }
  }

  public void linkSshKeys(Collection<IamSshKey> keys) {

    checkNotNull(keys);
    for (IamSshKey key : keys) {
      link(sshKeys, key, this);
    }
  }

  public void unlinkSshKeys(Collection<IamSshKey> keys) {

    checkNotNull(keys);
    for (IamSshKey key : keys) {
      unlink(sshKeys.iterator(), key);
    }
  }

  public void linkX509Certificates(Collection<IamX509Certificate> certs) {

    checkNotNull(certs);

    for (IamX509Certificate c : certs) {
      if (!getX509Certificates().contains(c)) {
        Date addedTimestamp = new Date();
        c.setAccount(this);
        c.setCreationTime(addedTimestamp);
        c.setLastUpdateTime(addedTimestamp);

        getX509Certificates().add(c);
      }
    }
  }

  public void unlinkX509Certificates(Collection<IamX509Certificate> certs) {

    checkNotNull(certs);
    for (IamX509Certificate c : certs) {
      unlink(x509Certificates.iterator(), c);
    }
  }

  private <T extends IamAccountRef> void unlink(Iterator<T> it, T id) {
    if (id == null) {
      return;
    }
    while (it.hasNext()) {
      T toBeRemoved = it.next();
      if (id.equals(toBeRemoved)) {
        toBeRemoved.setAccount(null);
        it.remove();
        break;
      }
    }
  }

  private <T extends IamAccountRef> void link(Collection<T> c, T id, IamAccount owner) {
    if (id == null) {
      return;
    }
    if (!c.contains(id)) {
      c.add(id);
      id.setAccount(owner);
    }
  }

  public String getConfirmationKey() {

    return confirmationKey;
  }

  public void setConfirmationKey(final String confirmationKey) {

    this.confirmationKey = confirmationKey;
  }

  public String getResetKey() {

    return resetKey;
  }

  public void setResetKey(final String resetKey) {

    this.resetKey = resetKey;
  }

  public IamRegistrationRequest getRegistrationRequest() {

    return registrationRequest;
  }

  public void setRegistrationRequest(final IamRegistrationRequest registrationRequest) {

    this.registrationRequest = registrationRequest;
  }

  public IamAupSignature getAupSignature() {
    return aupSignature;
  }

  public void setAupSignature(IamAupSignature aupSignature) {
    this.aupSignature = aupSignature;
  }

  public void touch() {

    setLastUpdateTime(new Date());
  }

  public void touch(Clock clock) {
    setLastUpdateTime(Date.from(clock.instant()));
  }

  @Override
  public int hashCode() {

    final int prime = 31;
    int result = 1;
    result = prime * result + ((uuid == null) ? 0 : uuid.hashCode());
    return result;
  }

  @Override
  public boolean equals(final Object obj) {

    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    IamAccount other = (IamAccount) obj;
    if (uuid == null) {
      if (other.uuid != null)
        return false;
    } else if (!uuid.equals(other.uuid))
      return false;
    return true;
  }

  public boolean isProvisioned() {
    return provisioned;
  }

  public void setProvisioned(boolean provisioned) {
    this.provisioned = provisioned;
  }

  public Date getLastLoginTime() {
    return lastLoginTime;
  }

  public void setLastLoginTime(Date lastLoginTime) {
    this.lastLoginTime = lastLoginTime;
  }

  public Set<IamScopePolicy> getScopePolicies() {
    return scopePolicies;
  }

  public void setScopePolicies(Set<IamScopePolicy> scopePolicies) {
    this.scopePolicies = scopePolicies;
  }

  public Set<IamGroupRequest> getGroupRequest() {
    return groupRequests;
  }

  public void setGroupRequest(Set<IamGroupRequest> groupRequests) {
    this.groupRequests = groupRequests;
  }

  public Set<IamAccountGroupMembership> getGroups() {
    return groups;
  }

  public void setGroups(Set<IamAccountGroupMembership> groupMemberships) {
    this.groups = groupMemberships;
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


  public Optional<IamLabel> getLabelByPrefixAndName(String prefix, String name) {
    for (IamLabel l : getLabels()) {
      if (l.getName().equals(name) && prefix.equals(l.getPrefix())) {
        return Optional.of(l);
      }
    }
    return Optional.empty();
  }

  public Optional<IamLabel> getLabelByName(String name) {
    for (IamLabel l : getLabels()) {
      if (l.getName().equals(name) && Objects.isNull(l.getPrefix())) {
        return Optional.of(l);
      }
    }
    return Optional.empty();
  }

  public Optional<IamLabel> removeLabelByNameAndPrefix(String prefix, String name) {

    Optional<IamLabel> label = getLabelByPrefixAndName(prefix, name);
    if (label.isPresent()) {
      getLabels().remove(label.get());
    }
    return label;
  }

  public Optional<IamLabel> removeLabelByName(String name) {
    Optional<IamLabel> label = getLabelByName(name);
    if (label.isPresent()) {
      getLabels().remove(label.get());
    }
    return label;
  }

  @Override
  public String toString() {
    return "IamAccount [id=" + id + ", uuid=" + uuid + ", username=" + username + ", active="
        + active + "]";
  }

  public static IamAccount newAccount() {
    IamAccount newAccount = new IamAccount();
    IamUserInfo userInfo = new IamUserInfo();
    userInfo.setIamAccount(newAccount);
    newAccount.setUserInfo(userInfo);
    return newAccount;
  }

  public Date getEndTime() {
    return endTime;
  }

  public void setEndTime(Date endTime) {
    this.endTime = endTime;
  }
}
