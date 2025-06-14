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
package it.infn.mw.iam.core;

public enum IamNotificationType {
  CONFIRMATION, RESETPASSWD, ACTIVATED, REJECTED, GROUP_MEMBERSHIP, AUP_REMINDER, AUP_EXPIRATION, AUP_SIGNATURE_REQUEST,
   ACCOUNT_SUSPENDED, ACCOUNT_RESTORED, CLIENT_STATUS, CERTIFICATE_LINK, MFA_ENABLE, MFA_DISABLE,
  SET_SERVICE_ACCOUNT, REVOKE_SERVICE_ACCOUNT
}
