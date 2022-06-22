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
package it.infn.mw.iam.audit.events.auth;

import org.springframework.security.authentication.event.AbstractAuthenticationEvent;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.utils.IamAuthenticationSuccessSerializer;

public class IamAuthenticationSuccessEvent extends IamAuthenticationEvent {

  private static final long serialVersionUID = 1L;

  @JsonSerialize(using = IamAuthenticationSuccessSerializer.class)
  final AbstractAuthenticationEvent sourceEvent;

  public IamAuthenticationSuccessEvent(AbstractAuthenticationEvent authEvent) {
    super(authEvent,
        String.format("%s authenticated succesfully", authEvent.getAuthentication().getName()));
    this.sourceEvent = authEvent;
  }

  public AbstractAuthenticationEvent getSourceEvent() {
    return sourceEvent;
  }

}
