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
package it.infn.mw.iam.test.oauth.scope;

import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.springframework.test.web.servlet.ResultMatcher;

import com.fasterxml.jackson.core.type.TypeReference;

import it.infn.mw.iam.api.common.LabelDTO;

public interface StructuredScopeTestSupportConstants {

  static final String PASSWORD_CLIENT_ID = "password-grant";
  static final String PASSWORD_CLIENT_SECRET = "secret";

  static final String CLIENT_CREDENTIALS_CLIENT_ID = "client-cred";
  static final String CLIENT_CREDENTIALS_CLIENT_SECRET = "secret";

  static final String EXCHANGE_CLIENT_ID = "token-exchange-actor";
  static final String EXCHANGE_CLIENT_SECRET = "secret";

  static final String LOOKUP_CLIENT_ID = "token-lookup-client";
  static final String LOOKUP_CLIENT_SECRET = "secret";

  static final String IMPLICIT_CLIENT_ID = "implicit-flow-client";
  static final String IMPLICIT_CLIENT_REDIRECT_URL = "http://localhost:9876/implicit";

  static final String TEST_CLIENT_ID = "client";
  static final String TEST_CLIENT_SECRET = "secret";
  static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  static final String POST_CLIENT_ID = "post-client";
  static final String POST_CLIENT_SECRET = "secret";

  static final String AUTHORIZE_ENDPOINT = "/authorize";
  static final String DEVICE_CODE_ENDPOINT = "/devicecode";
  static final String DEVICE_CODE_USER_ENDPOINT = "/device";
  static final String TOKEN_ENDPOINT = "/token";
  static final String USERINFO_ENDPOINT = "/userinfo";
  static final String INTROSPECTION_ENDPOINT = "/introspect";
  static final String REVOCATION_ENDPOINT = "/revoke";
  static final String REGISTER_ENDPOINT = "/iam/api/client-registration";

  static final String PUBLIC_DEVICE_CODE_CLIENT_ID = "public-dc-client";

  static final String DEVICE_CODE_CLIENT_ID = "device-code-client";
  static final String DEVICE_CODE_CLIENT_SECRET = "secret";

  static final String DEVICE_USER_URL = "http://localhost:8080/device";
  static final String DEVICE_USER_VERIFY_URL = "http://localhost:8080/device/verify";
  static final String DEVICE_USER_APPROVE_URL = "http://localhost:8080/device/approve";

  static final String PROTECTED_RESOURCE_ID = "protected-resource";
  static final String PROTECTED_RESOURCE_SECRET = "secret";

  static final String SCIM_CLIENT_RO_ID = "scim-client-ro";
  static final String SCIM_CLIENT_RO_SECRET = "secret";
  static final String SCIM_CLIENT_RW_ID = "scim-client-rw";
  static final String SCIM_CLIENT_RW_SECRET = "secret";

  static final String SCIM_USERS = "/scim/Users";
  static final String SCIM_GROUPS = "/scim/Groups";
  static final String SCIM_ME = "/scim/Me";

  static final String LOGIN_URL = "/login";
  static final String TEST_USERNAME = "test";
  static final String TEST_PASSWORD = "password";
  static final String TEST_UUID = "80e5fb8d-b7c8-451a-89ba-346ae278a66f";
  static final String TEST_NAME = "Test User";
  static final String TEST_EMAIL = "test@iam.test";

  static final String ANOTHER_USERNAME = "test_100";
  static final String ANOTHER_PASSWORD = "password";
  static final String ANOTHER_UUID = "f2ce8cb2-a1db-4884-9ef0-d8842cc02b4a";

  static final String ADMIN_USERNAME = "admin";
  static final String ADMIN_PASSWORD = "password";
  static final String ADMIN_UUID = "73f16d93-2441-4a50-88ff-85360d78c6b5";

  static final String EMPTY_SCOPES = "";

  static final String ORGANISATION_NAME = "indigo-dc";

  static final String TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
  static final String TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt";

  static final String[] USER_AUTHORITIES = new String[] { "ROLE_USER" };
  static final String[] ADMIN_AUTHORITIES = new String[] { "ROLE_USER", "ROLE_ADMIN" };

  static final String TEST_001_GROUP_UUID = "c617d586-54e6-411d-8e38-649677980001";
  static final String TEST_002_GROUP_UUID = "c617d586-54e6-411d-8e38-649677980002";

  static final String TEST_100_USER = "test_100";
  static final String TEST_100_USER_UUID = "f2ce8cb2-a1db-4884-9ef0-d8842cc02b4a";

  static final String CERN_USER = "cern-user";
  static final String CERN_USER_UUID = "e7de071b-578f-46ec-a2f1-6f9844a50aa5";

  public static final ResultMatcher OK = status().isOk();
  public static final ResultMatcher NO_CONTENT = status().isNoContent();
  public static final ResultMatcher BAD_REQUEST = status().isBadRequest();
  public static final ResultMatcher UNAUTHORIZED = status().isUnauthorized();
  public static final ResultMatcher FORBIDDEN = status().isForbidden();
  public static final ResultMatcher NOT_FOUND = status().isNotFound();
  public static final ResultMatcher CREATED = status().isCreated();

  public static final TypeReference<List<LabelDTO>> LIST_OF_LABEL_DTO =
      new TypeReference<List<LabelDTO>>() {};

  public static final ResultMatcher INVALID_PREFIX_ERROR_MESSAGE =
      jsonPath("$.error", containsString("invalid prefix (does not match"));

  public static final ResultMatcher PREFIX_TOO_LONG_ERROR_MESSAGE =
      jsonPath("$.error", containsString("invalid prefix length"));

  public static final ResultMatcher NAME_REQUIRED_ERROR_MESSAGE =
      jsonPath("$.error", containsString("name is required"));

  public static final ResultMatcher INVALID_NAME_ERROR_MESSAGE =
      jsonPath("$.error", containsString("invalid name (does not match"));

  public static final ResultMatcher INVALID_VALUE_ERROR_MESSAGE = jsonPath("$.error",
      containsString("Invalid label: The string must not contain any new line or carriage return"));

  public static final ResultMatcher NAME_TOO_LONG_ERROR_MESSAGE =
      jsonPath("$.error", containsString("invalid name length"));

  public static final ResultMatcher VALUE_TOO_LONG_ERROR_MESSAGE =
      jsonPath("$.error", containsString("invalid value length"));
}
