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

import it.infn.mw.iam.persistence.model.SystemScope;

public class ScopeUpdatedEvent extends ScopeEvent {

  private static final long serialVersionUID = -2464733224199680363L;

  private final SystemScope previousScope;

  public ScopeUpdatedEvent(Object source, SystemScope scope, SystemScope previousScope, String message) {
    super(source, scope, message);
    this.previousScope = previousScope;
  }

  public SystemScope getPreviousScope() {
    return previousScope;
  }
}
