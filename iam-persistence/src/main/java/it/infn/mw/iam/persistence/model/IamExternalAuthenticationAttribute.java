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
public class IamExternalAuthenticationAttribute implements Serializable {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

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
    // empty on purpose
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
