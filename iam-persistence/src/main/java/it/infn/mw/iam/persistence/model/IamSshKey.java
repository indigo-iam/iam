package it.infn.mw.iam.persistence.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "iam_ssh_key")
public class IamSshKey implements IamAccountRef {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 36, unique = true)
  private String label;

  @Column(name = "is_primary")
  boolean primary;

  @Column(name = "fingerprint", length = 48, unique = true, nullable = false)
  private String fingerprint;

  @Lob
  @Column(name = "val", length = 3072)
  private String value;

  @ManyToOne
  private IamAccount account;

  public IamSshKey() {

  }

  public IamSshKey(String value) {

	setValue(value);
  }

  public Long getId() {

    return id;
  }

  public void setId(Long id) {

    this.id = id;
  }

  public String getLabel() {

    return label;
  }

  public void setLabel(String label) {

    this.label = label;
  }

  public String getValue() {

    return value;
  }

  public void setValue(String value) {

    this.value = value;
  }

  public String getFingerprint() {

    return fingerprint;
  }

  public void setFingerprint(String fingerprint) {

    this.fingerprint = fingerprint;
  }

  @Override
  public IamAccount getAccount() {

    return account;
  }

  @Override
  public void setAccount(IamAccount account) {

    this.account = account;
  }

  public boolean isPrimary() {

    return primary;
  }

  public void setPrimary(boolean primary) {

    this.primary = primary;
  }

  @Override
  public int hashCode() {

	final int prime = 31;
	int result = 1;
	result = prime * result + ((value == null) ? 0 : value.hashCode());
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
	IamSshKey other = (IamSshKey) obj;
	if (value == null) {
	  if (other.value != null)
		return false;
	} else if (!value.equals(other.value))
	  return false;
	return true;
  }

}
