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

public final class RegexUtil {

    // Regex matches password with at least one lowercase letter, one uppercase
    // letter, one number, one symbol and minimum length of 8 characters
    public static final String PASSWORD_REGEX = "^(?=.*[\\p{Lower}])(?=.*[\\p{Upper}])(?=.*[\\p{Digit}])(?=.*[\\p{Punct}]).{8,}([^\\r\\t\\v\\f\\n]+)$";
    public static final String PASSWORD_REGEX_MESSAGE_ERROR = "The password must include at least one uppercase letter, one lowercase letter, one number one symbol (e.g., @$!%*?&) and must contain at least 8 characters for greater security.";
}

    // ^(?=.*[[:lower:]])(?=.*[[:upper:]])(?=.*[[:digit:]])(?=.*[[:punct:]]).{8,}
    // public static final String PASSWORD_REGEX = "^(?=.*[\\p{Lower}])(?=.*[\\p{Upper}])(?=.*[\\p{Digit}])(?=.*[\\p{Punct}]).{8,}$";
    // public static final String PASSWORD_REGEX_MESSAGE_ERROR = "The password must include at least one uppercase letter, one lowercase letter, one number one symbol (e.g., @$!%*?&) and must contain at least 8 characters for greater security.";
