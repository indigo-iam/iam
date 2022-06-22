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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Strings.isNullOrEmpty;

import org.springframework.security.oauth2.provider.ClientDetails;

@SuppressWarnings("deprecation")
public class ByScopeClientMatcher implements ClientMatcher {

  final String scope;
  
  public ByScopeClientMatcher(String scope) {
    checkArgument(!isNullOrEmpty(scope), "<null> or empty scope not allowed");
    this.scope = scope;
  }

  @Override
  public boolean matchesClient(ClientDetails client) {
    return client.getScope().contains(scope);
  }

  @Override
  public int rank() {
    return 1;
  }
}
