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
package it.infn.mw.iam.api.proxy;

import javax.validation.constraints.Min;

import org.hibernate.validator.constraints.Length;

public class ProxyCertificateRequestDTO {
  @Length(max=128, message="invalid issuer: max length exceeded (128 characters)")
  String issuer;
  
  @Min(value=120, message="invalid lifetime: minimum is 120 seconds")
  Long lifetimeSecs;

  
  public Long getLifetimeSecs() {
    return lifetimeSecs;
  }

  public void setLifetimeSecs(Long lifetimeSecs) {
    this.lifetimeSecs = lifetimeSecs;
  }

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }
}
