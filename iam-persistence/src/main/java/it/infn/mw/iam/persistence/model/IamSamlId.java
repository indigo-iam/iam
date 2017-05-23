package it.infn.mw.iam.persistence.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "iam_saml_id", 
indexes = {@Index(columnList="idpId,attribute_id,userId", name="IDX_IAM_SAML_ID_1")})
public class IamSamlId implements IamAccountRef {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne
  @JoinColumn(name = "account_id")
  IamAccount account;

  @Column(nullable = false, length = 256)
  String idpId;

  @Column(name = "attribute_id", nullable=false, length = 256)
  String attributeId;

  @Column(nullable = false, length = 256)
  String userId;


  public IamSamlId(String idpId, String attributeId, String userId) {
    setIdpId(idpId);
    setAttributeId(attributeId);
    setUserId(userId);
  }

  public IamSamlId() {}

  public Long getId() {

    return id;
  }

  public void setId(Long id) {

    this.id = id;
  }

  @Override
  public IamAccount getAccount() {

    return account;
  }

  @Override
  public void setAccount(IamAccount account) {

    this.account = account;
  }

  public String getIdpId() {

    return idpId;
  }

  public void setIdpId(String idpId) {

    this.idpId = idpId;
  }

  public String getUserId() {

    return userId;
  }

  public void setUserId(String userId) {

    this.userId = userId;
  }


  public String getAttributeId() {
    return attributeId;
  }

  public void setAttributeId(String attributeId) {
    this.attributeId = attributeId;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((attributeId == null) ? 0 : attributeId.hashCode());
    result = prime * result + ((idpId == null) ? 0 : idpId.hashCode());
    result = prime * result + ((userId == null) ? 0 : userId.hashCode());
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
    IamSamlId other = (IamSamlId) obj;
    if (attributeId == null) {
      if (other.attributeId != null)
        return false;
    } else if (!attributeId.equals(other.attributeId))
      return false;
    if (idpId == null) {
      if (other.idpId != null)
        return false;
    } else if (!idpId.equals(other.idpId))
      return false;
    if (userId == null) {
      if (other.userId != null)
        return false;
    } else if (!userId.equals(other.userId))
      return false;
    return true;
  }

  @Override
  public String toString() {
    return "IamSamlId [idpId=" + idpId + ", attributeId=" + attributeId + ", userId=" + userId
        + "]";
  }

}
