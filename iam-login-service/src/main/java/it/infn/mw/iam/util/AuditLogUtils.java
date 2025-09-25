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

import java.text.ParseException;

import com.nimbusds.jwt.JWTParser;

public class AuditLogUtils {

  private AuditLogUtils() {
    // empty constructor
  }

  /**
   * Keeps only a certain percentage of the string passed as argument
   * 
   * @param s The string to reduce
   * @param p The percentage of the string to keep from the first character on
   * @return the reduced string
   */
  public static String reduce(String s, double p) {
    return s.substring(0, (int) Math.ceil(s.length() * p));
  }

  public static String getPayload(String token) {
    try {
      return JWTParser.parse(token).getParsedString();
    } catch (ParseException e) {
      return "";
    }
  }

}
