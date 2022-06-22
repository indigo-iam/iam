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

import static com.google.common.base.Strings.isNullOrEmpty;
import static java.util.Collections.emptyList;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import com.google.common.base.Splitter;

public class VOMSControllerSupport {

  private final Splitter commaSplitter = Splitter.on(',').omitEmptyStrings().trimResults();

  protected List<VOMSFqan> parseRequestedFqansString(String fqans) {
    if (isNullOrEmpty(fqans)) {
      return emptyList();
    } else {
      return commaSplitter.splitToList(fqans)
        .stream()
        .map(VOMSFqan::fromString)
        .collect(Collectors.toList());
    }
  }

  protected long getRequestedLifetime(Long lifetime) {

    if (Objects.isNull(lifetime)) {
      return -1;
    }

    return lifetime;
  }

  protected List<String> parseRequestedTargetsString(String targets) {
    if (isNullOrEmpty(targets)) {
      return Collections.emptyList();
    }
    return commaSplitter.splitToList(targets);
  }

}
