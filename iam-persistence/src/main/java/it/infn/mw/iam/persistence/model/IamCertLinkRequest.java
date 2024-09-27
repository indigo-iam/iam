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

import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.CascadeType;

@Entity
@Table(name = "iam_cert_link_request")
public class IamCertLinkRequest extends IamRequest {

  private static final long serialVersionUID = 1L;

  @OneToOne(cascade = CascadeType.PERSIST)
  @JoinColumn(name = "iam_x509_cert_id")
  private IamX509Certificate certificate;


  public IamCertLinkRequest() {
    // empty constructor
  }

  public IamX509Certificate getCertificate() {
    return certificate;
  }

  public void setCertificate(IamX509Certificate certificate) {
    this.certificate = certificate;
  }

  @Override
  public String toString() {
    return String.format(
        "IamCertLinkRequest [id=%s, uuid=%s, accountUsername=%s, certificateName=%s, subject=%s, issuer=%s, status=%s,creationTime=%s, lastUpdateTime=%s]",
        getId(), getUuid(), getAccount().getUsername(), getCertificate().getLabel(),
        getCertificate().getSubjectDn(), getCertificate().getIssuerDn(), getStatus(),
        getCreationTime(), getLastUpdateTime());
  }
}
