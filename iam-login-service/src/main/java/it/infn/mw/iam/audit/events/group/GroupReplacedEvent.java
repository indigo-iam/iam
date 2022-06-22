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
package it.infn.mw.iam.audit.events.group;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.utils.IamGroupSerializer;
import it.infn.mw.iam.persistence.model.IamGroup;

public class GroupReplacedEvent extends GroupEvent {

  private static final long serialVersionUID = -2464733224199680363L;

  @JsonSerialize(using=IamGroupSerializer.class)
  private final IamGroup previousGroup;

  public GroupReplacedEvent(Object source, IamGroup group, IamGroup previousGroup, String message) {
    super(source, group, message);
    this.previousGroup = previousGroup;
  }

  public IamGroup getPreviousGroup() {
    return previousGroup;
  }
}
