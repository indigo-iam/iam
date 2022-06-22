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
package it.infn.mw.iam.audit.events.scope_policy;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.utils.IamScopePolicySerializer;
import it.infn.mw.iam.persistence.model.IamScopePolicy;

public abstract class ScopePolicyEvent extends IamAuditApplicationEvent {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;
  
  @JsonSerialize(using=IamScopePolicySerializer.class)
  private final IamScopePolicy policy;
  
  protected ScopePolicyEvent(Object source, String message, IamScopePolicy policy) {
    super(IamEventCategory.SCOPE_POLICY, source, message);
    this.policy = policy;
  }

  public IamScopePolicy getPolicy() {
    return policy;
  }

}
