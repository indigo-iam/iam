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
package it.infn.mw.iam.audit.events.registration;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.utils.IamRegistrationRequestSerializer;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public class RegistrationEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = -3428745338283606683L;

  @JsonSerialize(using=IamRegistrationRequestSerializer.class)
  private final IamRegistrationRequest request;

  public RegistrationEvent(Object source, IamRegistrationRequest request, String message) {
    super(IamEventCategory.REGISTRATION,source, message);
    this.request = request;
  }

  public IamRegistrationRequest getRequest() {
    return request;
  }


}
