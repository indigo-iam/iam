package it.infn.mw.iam.persistence.model;

import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
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

/**
 * 
 *
 */
@Entity
@Table(name = "iam_account")
public class IamAccount {

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
  @Column(nullable = false)
  Date creationTime;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(nullable = false)
  Date lastUpdateTime;

  @OneToOne(cascade = CascadeType.ALL)
  @JoinColumn(name = "user_info_id")
  private IamUserInfo userInfo;

  @ManyToMany
  @JoinTable(name = "iam_account_authority",
      joinColumns = @JoinColumn(name = "account_id", referencedColumnName = "id") ,
      inverseJoinColumns = @JoinColumn(name = "authority_id", referencedColumnName = "id") )
  private Set<IamAuthority> authorities = new HashSet<>();

  @ManyToMany
  @JoinTable(name = "iam_account_group",
      joinColumns = @JoinColumn(name = "account_id", referencedColumnName = "id") ,
      inverseJoinColumns = @JoinColumn(name = "group_id", referencedColumnName = "id") )
  private Set<IamGroup> groups = new HashSet<>();

  @OneToMany(mappedBy = "account", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
  private List<IamSamlId> samlIds = new LinkedList<>();

  @OneToMany(mappedBy = "account", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
  private List<IamOidcId> oidcIds = new LinkedList<>();

  @OneToMany(mappedBy = "account", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
  private List<IamSshKey> sshKeys = new LinkedList<>();

  @OneToMany(mappedBy = "account", cascade = CascadeType.ALL, fetch = FetchType.EAGER,
      orphanRemoval = true)
  private List<IamX509Certificate> x509Certificates = new LinkedList<>();

  @Column(name = "confirmation_key", unique = true, length = 36)
  private String confirmationKey;

  @Column(name = "reset_key", unique = true, length = 36)
  private String resetKey;

  @OneToOne(cascade = CascadeType.REMOVE, mappedBy = "account")
  private IamRegistrationRequest registrationRequest;

  public IamAccount() {}

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

  public Set<IamGroup> getGroups() {

    return groups;
  }

  public void setGroups(Set<IamGroup> groups) {

    this.groups = groups;
  }

  public boolean isMemberOf(IamGroup group) {

    return groups.contains(group);
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

  public List<IamSamlId> getSamlIds() {

    return samlIds;
  }

  public void setSamlIds(List<IamSamlId> samlIds) {

    Preconditions.checkNotNull(samlIds);
    this.samlIds = samlIds;
  }

  public List<IamOidcId> getOidcIds() {

    return oidcIds;
  }

  public void setOidcIds(List<IamOidcId> oidcIds) {

    Preconditions.checkNotNull(oidcIds);
    this.oidcIds = oidcIds;
  }

  public List<IamSshKey> getSshKeys() {

    return sshKeys;
  }

  public void setSshKeys(List<IamSshKey> sshKeys) {

    Preconditions.checkNotNull(sshKeys);
    this.sshKeys = sshKeys;
  }

  public List<IamX509Certificate> getX509Certificates() {

    return x509Certificates;
  }

  public void setX509Certificates(List<IamX509Certificate> x509Certificates) {

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

  public void touch() {

    setLastUpdateTime(new Date());
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

  @Override
  public String toString() {
    return "IamAccount [id=" + id + ", uuid=" + uuid + ", username=" + username + ", password="
        + password + ", active=" + active + ", creationTime=" + creationTime + ", lastUpdateTime="
        + lastUpdateTime + ", userInfo=" + userInfo + ", authorities=" + authorities + ", groups="
        + groups + ", samlIds=" + samlIds + ", oidcIds=" + oidcIds + ", sshKeys=" + sshKeys
        + ", x509Certificates=" + x509Certificates + ", confirmationKey=" + confirmationKey
        + ", resetKey=" + resetKey + ", registrationRequest=" + registrationRequest + "]";
  }

}
