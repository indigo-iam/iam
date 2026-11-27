/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2026
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

import java.util.regex.Pattern;

public final class LogUtils {

  private static final Pattern UNSAFE_LOG_CHARS = Pattern.compile("[\\p{Cc}\\p{Zl}\\p{Zp}]");

  private LogUtils() {}

  /**
   * Replaces control characters and Unicode line and paragraph separators for plain-text logging.
   * Returns null unchanged. This method is not intended for sanitizing domain data.
   */
  public static String sanitizeForLogging(String value) {
    if (value == null) {
      return null;
    }
    return UNSAFE_LOG_CHARS.matcher(value).replaceAll("_");
  }
}
