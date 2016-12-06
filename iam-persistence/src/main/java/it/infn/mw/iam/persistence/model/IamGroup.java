package it.infn.mw.iam.persistence.model;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "iam_group")
public class IamGroup {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 36, unique = true)
  private String uuid;

  @Column(nullable = false, length = 255, unique = true)
  private String name;

  @Column(nullable = true, length = 512)
  private String description;

  @ManyToMany(mappedBy = "groups")
  private Set<IamAccount> accounts = new HashSet<IamAccount>();

  @Temporal(TemporalType.TIMESTAMP)
  @Column(nullable = false)
  Date creationTime;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(nullable = false)
  Date lastUpdateTime;

  public IamGroup() {

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

  public Set<IamAccount> getAccounts() {

    return accounts;
  }

  public void setAccounts(Set<IamAccount> accounts) {

    this.accounts = accounts;
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

    return "IamGroup [id=" + id + ", uuid=" + uuid + ", name=" + name + ", description="
        + description + ", creationTime=" + creationTime + ", lastUpdateTime=" + lastUpdateTime
        + "]";
  }

}
