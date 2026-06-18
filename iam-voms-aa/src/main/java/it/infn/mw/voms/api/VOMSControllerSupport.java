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
package it.infn.mw.voms.api;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class VOMSControllerSupport {

  protected List<VOMSFqan> parseRequestedFqansString(String fqans) {

    if (fqans == null || fqans.isEmpty()) {
      return List.of();
    }

    return Arrays.stream(fqans.split(","))
      .map(String::trim)
      .filter(s -> !s.isEmpty())
      .map(VOMSFqan::fromString)
      .toList();
  }

  protected long getRequestedLifetime(Long lifetime) {

    if (Objects.isNull(lifetime)) {
      return -1;
    }

    return lifetime;
  }

  protected List<String> parseRequestedTargetsString(String targets) {
    if (targets == null || targets.isEmpty()) {
      return List.of();
    }

    return Arrays.stream(targets.split(","))
      .map(String::trim)
      .filter(s -> !s.isEmpty())
      .toList();
  }

}
