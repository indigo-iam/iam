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

import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public class RegistrationConfirmEvent extends RegistrationEvent {

  private static final long serialVersionUID = 8266010241487555711L;

  public RegistrationConfirmEvent(Object source, IamRegistrationRequest request, String message) {
    super(source, request, message);
  }

  public String getConfirmationKey(){
    return getRequest().getAccount().getConfirmationKey();
  }
}
