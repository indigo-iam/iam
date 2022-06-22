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
package it.infn.mw.iam.test.util.oauth;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import org.springframework.security.oauth2.provider.OAuth2Request;

import com.google.common.collect.Sets;

@SuppressWarnings("deprecation")
public class MockOAuth2Request extends OAuth2Request {

  private static final long serialVersionUID = -8547059375050883345L;

  public MockOAuth2Request(String clientId, String[] scopes) {
    setClientId(clientId);

    if (!Objects.isNull(scopes)) {
      setScope(Sets.newHashSet(scopes));
    } else {
      setScope(Collections.emptySet());
    }
  }

  @Override
  public boolean isApproved() {
    return true;
  }
  
  @Override
  public void setRequestParameters(Map<String, String> requestParameters) {
    super.setRequestParameters(requestParameters);
  }
}
