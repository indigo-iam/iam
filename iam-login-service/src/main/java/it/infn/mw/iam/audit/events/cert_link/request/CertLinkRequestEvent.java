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
package it.infn.mw.iam.audit.events.cert_link.request;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.events.IamEventCategory;
import it.infn.mw.iam.audit.utils.IamCertLinkRequestSerializer;
import it.infn.mw.iam.persistence.model.IamCertLinkRequest;

public abstract class CertLinkRequestEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = 1L;

  @JsonSerialize(using = IamCertLinkRequestSerializer.class)
  private final IamCertLinkRequest certLinkRequest;

  public CertLinkRequestEvent(Object source, IamCertLinkRequest certLinkRequest, String message) {
    super(IamEventCategory.CERTIFICATE_LINK, source, message);
    this.certLinkRequest = certLinkRequest;
  }

  public IamCertLinkRequest getCertLinkRequest() {
    return certLinkRequest;
  }
}
