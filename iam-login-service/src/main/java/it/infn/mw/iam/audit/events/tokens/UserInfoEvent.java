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
package it.infn.mw.iam.audit.events.tokens;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.events.IamEventCategory;
import it.infn.mw.iam.core.userinfo.UserInfoResponse;

public class UserInfoEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = 1L;

  private final String authenticatedClientId;
  private final String returnedSub;

  public UserInfoEvent(Object source, String clientId, UserInfoResponse response) {
    super(IamEventCategory.TOKEN, source, "UserInfo request");
    this.authenticatedClientId = clientId;
    this.returnedSub = response.getSub();
  }

  public String getAuthenticatedClientId() {
    return authenticatedClientId;
  }

  public String getReturnedSub() {
    return returnedSub;
  }

}
