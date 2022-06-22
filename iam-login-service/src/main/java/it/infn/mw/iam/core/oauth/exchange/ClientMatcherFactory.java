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
package it.infn.mw.iam.core.oauth.exchange;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.persistence.model.IamClientMatchingPolicy;

public class ClientMatcherFactory {

  private ClientMatcherFactory() {
    // empty on purpose
  }
  
  public static ClientMatcher newClientMatcher(IamClientMatchingPolicy clientMatchingPolicy) {
    switch (clientMatchingPolicy.getType()) {
      case ANY:
        return new AnyClientMatcher();

      case BY_ID:
        return new ByIdClientMatcher(clientMatchingPolicy.getMatchParam());

      case BY_SCOPE:
        return new ByScopeClientMatcher(clientMatchingPolicy.getMatchParam());

      default:
        throw new IllegalArgumentException(
            "Unsupported client matcher type: " + clientMatchingPolicy.getType());
    }
  }

}
