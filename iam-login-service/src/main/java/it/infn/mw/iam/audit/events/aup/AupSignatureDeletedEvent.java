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
package it.infn.mw.iam.audit.events.aup;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.events.IamEventCategory;
import it.infn.mw.iam.audit.utils.IamAupSignatureSerializer;
import it.infn.mw.iam.persistence.model.IamAupSignature;

public class AupSignatureDeletedEvent extends IamAuditApplicationEvent {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  @JsonSerialize(using = IamAupSignatureSerializer.class)
  final IamAupSignature signature;

  public AupSignatureDeletedEvent(Object source, String message, IamAupSignature signature) {
    super(IamEventCategory.AUP, source, message);
    this.signature = signature;
  }

  public static AupSignatureDeletedEvent deletedByClient(Object source, String clientId,
      IamAupSignature signature) {
    String message = String.format("Client %s deleted the AUP signature of %s user", clientId,
        signature.getAccount().getUsername());
    return new AupSignatureDeletedEvent(source, message, signature);
  }

  public static AupSignatureDeletedEvent deletedByUser(Object source, String userId,
      IamAupSignature signature) {
    String message = String.format("User %s deleted the AUP signature of %s user", userId,
        signature.getAccount().getUsername());
    return new AupSignatureDeletedEvent(source, message, signature);
  }

}
