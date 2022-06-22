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
package it.infn.mw.iam.audit.events.group.label;

import static java.lang.String.format;

import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamLabel;

public class GroupLabelRemovedEvent extends GroupLabelEvent {
  private static final long serialVersionUID = -7951684086863051775L;

  public static final String MESSAGE = "Label '%s' removed for group '%s'";

  public GroupLabelRemovedEvent(Object source, IamGroup group, IamLabel label) {
    super(source, group, label, format(MESSAGE, label.qualifiedName(), group.getName()));
  }

}
