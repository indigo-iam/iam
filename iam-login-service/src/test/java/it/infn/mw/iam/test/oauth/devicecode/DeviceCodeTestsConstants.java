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
package it.infn.mw.iam.test.oauth.devicecode;

public interface DeviceCodeTestsConstants {

  public static final String DEVICE_CODE_ENDPOINT = "/devicecode";
  public static final String DEVICE_CODE_USER_ENDPOINT = "/device";
  public static final String TOKEN_ENDPOINT = "/token";
  public static final String USERINFO_ENDPOINT = "/userinfo";
  public static final String INTROSPECTION_ENDPOINT = "/introspect";

  public static final String PUBLIC_DEVICE_CODE_CLIENT_ID = "public-dc-client";

  public static final String DEVICE_CODE_CLIENT_ID = "device-code-client";
  public static final String DEVICE_CODE_CLIENT_SECRET = "secret";
  public static final String DEVICE_CODE_GRANT_TYPE =
      "urn:ietf:params:oauth:grant-type:device_code";

  public static final String DEVICE_USER_URL = "http://localhost:8080/device";
  public static final String DEVICE_USER_VERIFY_URL = "http://localhost:8080/device/verify";
  public static final String DEVICE_USER_APPROVE_URL = "http://localhost:8080/device/approve";

  public static final String LOGIN_URL = "/login";
  public static final String TEST_USERNAME = "test";
  public static final String TEST_PASSWORD = "password";

}
