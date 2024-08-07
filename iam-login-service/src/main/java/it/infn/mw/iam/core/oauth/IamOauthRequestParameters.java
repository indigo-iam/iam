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
package it.infn.mw.iam.core.oauth;

public abstract class IamOauthRequestParameters {

  public static final String URL = "devicecode";
  public static final String USER_URL = "device";

  public static final String REQUEST_USER_CODE_STRING = "requestUserCode";
  public static final String ERROR_STRING = "error";

  public static final String APPROVAL_ATTRIBUTE_KEY = "approved";

  public static final String APPROVE_DEVICE_PAGE = "iam/approveDevice";
  public static final String DEVICE_APPROVED_PAGE = "deviceApproved";

  public static final String REMEMBER_PARAMETER_KEY = "remember";

}
