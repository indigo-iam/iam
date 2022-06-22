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
package it.infn.mw.iam.audit;

public interface IamAuditField {
  final String SOURCE = "source";
  final String CATEGORY = "category";
  final String TYPE = "type";
  final String PRINCIPAL = "principal";
  final String MESSAGE = "message";
  final String DETAILS = "details";
  final String FAILURE_TYPE = "failureType";
  final String TARGET = "target";
  final String GENERATED_BY = "generatedBy";
  final String ACCOUNT_UUID = "accountUuid";
  final String USER = "user";
  final String PREVIOUS_ACCOUNT_UUID = "previousAccountUuid";
  final String PREVIOUS_ACCOUNT_USERNAME = "previousAccountUsername";
  final String EXT_ACCOUNT_ISSUER = "extAccIssuer";
  final String EXT_ACCOUNT_SUBJECT = "extAccSubject";
  final String EXT_ACCOUNT_TYPE = "extAccountType";
  final String UPDATE_TYPE = "updateType";
  final String AUTHORITY = "authority";
  final String GROUP_UUID = "groupUuid";
  final String GROUP_NAME = "groupName";
  final String PREVIOUS_GROUP_UUID = "previousGroupUuid";
  final String PREVIOUS_GROUP_NAME = "previousGroupName";
  final String RESET_KEY = "resetKey";
  final String CONFIRMATION_KEY = "confirmationKey";
  final String REQUEST_UUID = "requestUuid";
  final String REQUEST_STATUS = "requestStatus";

}
