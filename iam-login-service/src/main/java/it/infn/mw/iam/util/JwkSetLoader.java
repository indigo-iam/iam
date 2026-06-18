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

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;

import org.springframework.core.io.Resource;

import com.google.common.io.CharStreams;
import com.nimbusds.jose.jwk.JWKSet;

public final class JwkSetLoader {

  private JwkSetLoader() {
    // Hides the implicit constructor
  }

  public static JWKSet load(Resource location) throws IOException, ParseException {
    if (location == null) {
      throw new IllegalArgumentException("Invalid null location");
    }
    if (!location.exists() || !location.isReadable()) {
      throw new IOException("Location doesn't exist or is not readable: " + location.toString());
    }
    try (var reader = new InputStreamReader(location.getInputStream(), StandardCharsets.UTF_8)) {
      return JWKSet.parse(CharStreams.toString(reader));
    }
  }
}
