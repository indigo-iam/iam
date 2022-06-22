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
package it.infn.mw.iam.util;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.US_ASCII;

import org.apache.commons.codec.binary.Base64;

public class BasicAuthenticationUtils {

  private BasicAuthenticationUtils() {
    // prevent instantiation
  }

  public static final String basicAuthHeaderValue(String username, String password) {
    StringBuilder builder = new StringBuilder();
    String auth = format("%s:%s", username, password);
    String encodedAuth = Base64.encodeBase64String(auth.getBytes(US_ASCII));
    
    builder.append("Basic ");
    builder.append(encodedAuth);
    return builder.toString();
  }
}
