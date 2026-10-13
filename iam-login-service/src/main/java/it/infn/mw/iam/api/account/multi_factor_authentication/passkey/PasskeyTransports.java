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
package it.infn.mw.iam.api.account.multi_factor_authentication.passkey;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Converts between the comma separated transports column of a passkey and the WebAuthn transport
 * hints exchanged with the browser
 */
public final class PasskeyTransports {

  private static final String SEPARATOR = ",";

  private static final Set<String> KNOWN_TRANSPORTS =
      Set.of("usb", "nfc", "ble", "hybrid", "internal", "smart-card");

  private PasskeyTransports() {
    // prevent instantiation
  }

  public static String toColumn(Collection<String> transports) {
    if (transports == null || transports.isEmpty()) {
      return null;
    }
    Set<String> known = new LinkedHashSet<>();
    for (String t : transports) {
      if (t != null && KNOWN_TRANSPORTS.contains(t.trim().toLowerCase())) {
        known.add(t.trim().toLowerCase());
      }
    }
    if (known.isEmpty()) {
      return null;
    }
    return String.join(SEPARATOR, known);
  }

  public static List<String> toList(String column) {
    if (column == null || column.isEmpty()) {
      return Collections.emptyList();
    }
    List<String> result = new ArrayList<>();
    for (String t : column.split(SEPARATOR)) {
      if (!t.isBlank()) {
        result.add(t.trim());
      }
    }
    return result;
  }
}
