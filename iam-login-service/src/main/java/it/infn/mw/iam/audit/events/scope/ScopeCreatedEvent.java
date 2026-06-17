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
package it.infn.mw.iam.audit.events.scope;

import org.mitre.oauth2.model.SystemScope;

public class ScopeCreatedEvent extends ScopeEvent {

  private static final long serialVersionUID = 8991030562775896932L;

  public ScopeCreatedEvent(Object source, SystemScope scope, String message) {
    super(source, scope, message);
  }

}