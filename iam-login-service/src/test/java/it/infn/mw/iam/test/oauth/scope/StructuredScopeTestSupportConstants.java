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

interface StructuredScopeTestSupportConstants {
  
  static final String PASSWORD_GRANT_TYPE = "password";
  static final String PASSWORD_CLIENT_ID = "password-grant";
  static final String PASSWORD_CLIENT_SECRET = "secret";
  
  static final String CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";
  static final String CLIENT_CREDENTIALS_CLIENT_ID = "client-cred";
  static final String CLIENT_CREDENTIALS_CLIENT_SECRET = "secret";

  static final String DEVICE_CODE_ENDPOINT = "/devicecode";
  static final String DEVICE_CODE_USER_ENDPOINT = "/device";
  static final String TOKEN_ENDPOINT = "/token";
  static final String USERINFO_ENDPOINT = "/userinfo";
  static final String INTROSPECTION_ENDPOINT = "/introspect";
  static final String REGISTER_ENDPOINT = "/register";

  static final String DEVICE_CODE_CLIENT_ID = "device-code-client";
  static final String DEVICE_CODE_CLIENT_SECRET = "secret";
  static final String DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

  static final String DEVICE_USER_URL = "http://localhost:8080/device";
  static final String DEVICE_USER_VERIFY_URL = "http://localhost:8080/device/verify";
  static final String DEVICE_USER_APPROVE_URL = "http://localhost:8080/device/approve";

  static final String LOGIN_URL = "/login";
  static final String TEST_USERNAME = "test";
  static final String TEST_PASSWORD = "password";
}
