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


public class NameUtils {

  public static String getFormatted(String givenName, String middleName, String familyName) {

    StringBuilder builder = new StringBuilder();
    builder.append(givenName);

    if (middleName != null && !middleName.isEmpty()) {
      builder.append(" ");
      builder.append(middleName);
    }

    builder.append(" ");
    builder.append(familyName);
    return builder.toString();
  }

}
