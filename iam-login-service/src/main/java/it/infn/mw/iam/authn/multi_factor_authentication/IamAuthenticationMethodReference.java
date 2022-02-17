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
package it.infn.mw.iam.authn.multi_factor_authentication;

public class IamAuthenticationMethodReference {

  public static final String AUTHENTICATION_METHOD_REFERENCE_CLAIM_STRING = "amr";

  public enum AuthenticationMethodReferenceValues {
    // Add additional values here if new authentication factors get added, e.g. HARDWARE_KEY("hwk")
    // Consult here for standardised reference values -
    // https://datatracker.ietf.org/doc/html/rfc8176

    PASSWORD("pwd"), ONE_TIME_PASSWORD("otp");

    private final String value;

    private AuthenticationMethodReferenceValues(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }
  }

  private String name;

  public IamAuthenticationMethodReference(String name) {
    this.name = name;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }
}
