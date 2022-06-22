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

public class RegistrationRejectEvent extends RegistrationEvent {

  private static final long serialVersionUID = -8142561937100438433L;

  public RegistrationRejectEvent(Object source, IamRegistrationRequest request, String message) {
    super(source, request, message);
  }
}
