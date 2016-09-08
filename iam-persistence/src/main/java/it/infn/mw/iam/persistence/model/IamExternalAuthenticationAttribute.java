package it.infn.mw.iam.persistence.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "iam_ext_authn_attr")
public class IamExternalAuthenticationAttribute {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  Long id;

  @ManyToOne(optional = false)
  @JoinColumn(name = "details_id")
  IamExternalAuthenticationDetails details;

  @Column(nullable = false, length = 255, updatable = false, name = "name")
  String name;

  @Column(nullable = false, updatable = false, length = 512, name = "value")
  String value;

  public IamExternalAuthenticationAttribute() {

  }

  public Long getId() {
    return id;
  }



  public void setId(Long id) {
    this.id = id;
  }



  public IamExternalAuthenticationDetails getDetails() {
    return details;
  }



  public void setDetails(IamExternalAuthenticationDetails details) {
    this.details = details;
  }



  public String getName() {
    return name;
  }



  public void setName(String name) {
    this.name = name;
  }



  public String getValue() {
    return value;
  }



  public void setValue(String value) {
    this.value = value;
  }



  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((details == null) ? 0 : details.hashCode());
    result = prime * result + ((name == null) ? 0 : name.hashCode());
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
    IamExternalAuthenticationAttribute other = (IamExternalAuthenticationAttribute) obj;
    if (details == null) {
      if (other.details != null)
        return false;
    } else if (!details.equals(other.details))
      return false;
    if (name == null) {
      if (other.name != null)
        return false;
    } else if (!name.equals(other.name))
      return false;
    if (value == null) {
      if (other.value != null)
        return false;
    } else if (!value.equals(other.value))
      return false;
    return true;
  }

  @Override
  public String toString() {
    return "ExtAuthAttribute [id=" + id + ", name=" + name + ", value=" + value + "]";
  }


}
