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

import static java.lang.String.format;
import static java.util.Objects.isNull;

import java.io.Serializable;

import javax.annotation.Generated;
import javax.persistence.Column;
import javax.persistence.Embeddable;

@Embeddable
public class IamLabel  implements Serializable{
  
  private static final long serialVersionUID = 1L;
  
  @Column(nullable=true, length=256)
  String prefix;
  
  @Column(nullable=false, length=64)
  String name;
  
  @Column(name="val", nullable=true, length=64)
  String value;
  
  public IamLabel() {
    // default constructor
  }

  public IamLabel(Builder builder) {
    this.prefix = builder.prefix;
    this.name = builder.name;
    this.value = builder.value;
  }
  
  public String getPrefix() {
    return prefix;
  }

  public void setPrefix(String prefix) {
    this.prefix = prefix;
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
  
  public String qualifiedName() {
    if (!isNull(prefix)) {
      return format("%s/%s",prefix, name);
    }
    
    return name;
  }

  @Override
  @Generated("eclipse")
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((name == null) ? 0 : name.hashCode());
    result = prime * result + ((prefix == null) ? 0 : prefix.hashCode());
    return result;
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
    IamLabel other = (IamLabel) obj;
    if (name == null) {
      if (other.name != null)
        return false;
    } else if (!name.equals(other.name))
      return false;
    if (prefix == null) {
      if (other.prefix != null)
        return false;
    } else if (!prefix.equals(other.prefix))
      return false;
    return true;
  }
  
  public static class Builder {
    String prefix;
    String name;
    String value;
    
    public Builder prefix(String prefix) {
      this.prefix = prefix;
      return this;
    }
    
    public Builder name(String name) {
      this.name = name;
      return this;
    }
    
    public Builder value(String value) {
      this.value = value;
      return this;
    }
    
    public IamLabel build() {
      return new IamLabel(this);
    }
  }
  
  public static Builder builder() {
    return new Builder();
  }
}
