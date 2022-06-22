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
package it.infn.mw.iam.notification;

import java.util.Optional;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamGroupRequest;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public interface NotificationFactory {

  IamEmailNotification createConfirmationMessage(IamRegistrationRequest request);

  IamEmailNotification createAccountActivatedMessage(IamRegistrationRequest request);

  IamEmailNotification createRequestRejectedMessage(IamRegistrationRequest request, Optional<String> motivation);

  IamEmailNotification createAdminHandleRequestMessage(IamRegistrationRequest request);

  IamEmailNotification createResetPasswordMessage(IamAccount account);

  IamEmailNotification createAdminHandleGroupRequestMessage(IamGroupRequest groupRequest);

  IamEmailNotification createGroupMembershipApprovedMessage(IamGroupRequest groupRequest);

  IamEmailNotification createGroupMembershipRejectedMessage(IamGroupRequest groupRequest);
}
