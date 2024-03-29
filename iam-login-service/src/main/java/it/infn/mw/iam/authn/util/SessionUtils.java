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
package it.infn.mw.iam.authn.util;

import javax.servlet.http.HttpSession;

public class SessionUtils {

  /**
   * Get the named stored session variable as a string. Return null if not found or not a string.
   *
   * @param session the session
   *
   * @param key the key
   *
   * @return the named stored session variable
   */
  public static String getStoredSessionString(HttpSession session, String key) {

    Object o = session.getAttribute(key);
    if (o != null && o instanceof String) {
      return (String) o;
    } else {
      return null;
    }
  }

}
