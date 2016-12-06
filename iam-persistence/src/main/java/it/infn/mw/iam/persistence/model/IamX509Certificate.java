package it.infn.mw.iam.persistence.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.Lob;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "iam_x509_cert")
public class IamX509Certificate implements IamAccountRef {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 36)
  private String label;

  @Column(nullable = false, length = 128, unique = true)
  private String certificateSubject;

  @Lob
  @Column(nullable = false, unique = true)
  private String certificate;

  @Column(name = "is_primary")
  private boolean primary;

  @ManyToOne(fetch=FetchType.EAGER)
  @JoinColumn(name="account_id")
  private IamAccount account;

  public IamX509Certificate() {}

  public IamX509Certificate(String certificate) {

    this.setCertificate(certificate);
  }

  @Override
  public int hashCode() {

	final int prime = 31;
	int result = 1;
	result = prime * result
	  + ((certificate == null) ? 0 : certificate.hashCode());
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
	IamX509Certificate other = (IamX509Certificate) obj;
	if (certificate == null) {
	  if (other.certificate != null)
		return false;
	} else if (!certificate.equals(other.certificate))
	  return false;
	return true;
  }

  @Override
  public IamAccount getAccount() {

    return account;
  }

  public String getCertificateSubject() {

    return certificateSubject;
  }

  public String getCertificate() {

    return certificate;
  }

  public Long getId() {

    return id;
  }

  public String getLabel() {

    return label;
  }

  public boolean isPrimary() {

    return primary;
  }

  @Override
  public void setAccount(IamAccount account) {

    this.account = account;
  }

  public void setCertificateSubject(String certificateSubject) {

    this.certificateSubject = certificateSubject;
  }

  public void setCertificate(String certificate) {

    this.certificate = certificate;
  }

  public void setId(Long id) {

    this.id = id;
  }

  public void setLabel(String label) {

    this.label = label;
  }

  public void setPrimary(boolean primary) {

    this.primary = primary;
  }

}
