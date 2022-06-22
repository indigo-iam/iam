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
import java.util.Objects;

import javax.annotation.Generated;
import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;

@Embeddable
public class IamClientMatchingPolicy implements Serializable {

  private static final long serialVersionUID = 1L;


  public enum ClientMatchingPolicyType {
    ANY,
    BY_ID,
    BY_SCOPE
  }

  @Enumerated(EnumType.STRING)
  @Column(name = "m_type", nullable = false, length = 8)
  ClientMatchingPolicyType type;

  @Column(name = "m_param", nullable = true, length = 256)
  String matchParam;


  @Override
  public int hashCode() {
    return Objects.hash(matchParam, type);
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
    IamClientMatchingPolicy other = (IamClientMatchingPolicy) obj;
    return Objects.equals(matchParam, other.matchParam) && type == other.type;
  }


  public ClientMatchingPolicyType getType() {
    return type;
  }


  public void setType(ClientMatchingPolicyType type) {
    this.type = type;
  }


  public String getMatchParam() {
    return matchParam;
  }


  public void setMatchParam(String matchParam) {
    this.matchParam = matchParam;
  }


}
