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
package it.infn.mw.iam.core.oidc;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class StaticTrustAnchorRepository implements TrustAnchorRepository {

  private final Set<String> trustedAnchors;

  public StaticTrustAnchorRepository(
      @Value("${openid-federation.trust-anchors}") List<String> anchors) {
    this.trustedAnchors = new HashSet<>(anchors);
  }

  @Override
  public boolean isTrusted(String entityId) {
    return trustedAnchors.contains(entityId);
  }
}
