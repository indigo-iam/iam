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

import java.util.List;

public abstract class IamOAuthRequestParameters {

  public static final String AUTHZ_CODE_URL = "/oauth/confirm_access";

  public static final String REQUEST_USER_CODE_STRING = "requestUserCode";

  public static final String APPROVE_AUTHZ_PAGE = "iam/approveClient";
  public static final String APPROVE_DEVICE_PAGE = "iam/approveDevice";
  public static final String DEVICE_APPROVED_PAGE = "deviceApproved";

  public static final String STATE_PARAMETER_KEY = "state";
  public static final String REMEMBER_PARAMETER_KEY = "remember";

  public static final String ERROR_STRING = "error";

  public static final String APPROVAL_ATTRIBUTE_KEY = "approved";

  public static final String RESOURCE_KEY = "resource";
  public static final String AUD_KEY = "aud";
  public static final String AUDIENCE_KEY = "audience";

  public static final String AUTHZ_CODE_KEY = "code";
  public static final String DEVICE_CODE_KEY = "device_code";
  public static final String REFRESH_TOKEN_KEY = "refresh_token";

  public static final List<String> AUD_KEYS = List.of(RESOURCE_KEY, AUD_KEY, AUDIENCE_KEY);

  private IamOAuthRequestParameters() {}

}
