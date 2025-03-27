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

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "iam_revoked_at")
public class IamRevokedAccessToken {

  @Id
  @Column(nullable = false, unique = true)
  String jti;

  @Column(nullable = false)
  Date exp;

  public String getJti() {
    return jti;
  }

  public void setJit(String jti) {
    this.jti = jti;
  }

  public Date getExp() {
    return exp;
  }

  public void setExp(Date exp) {
    this.exp = exp;
  }

  
}
