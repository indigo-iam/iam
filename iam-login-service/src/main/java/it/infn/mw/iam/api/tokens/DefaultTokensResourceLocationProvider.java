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
package it.infn.mw.iam.api.tokens;

import static it.infn.mw.iam.api.tokens.Constants.ACCESS_TOKENS_ENDPOINT;
import static it.infn.mw.iam.api.tokens.Constants.REFRESH_TOKENS_ENDPOINT;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class DefaultTokensResourceLocationProvider implements TokensResourceLocationProvider {

  @Value("${iam.baseUrl}")
  private String baseUrl;

  @Override
  public String accessTokenLocation(Long accessTokenId) {
    return String.format("%s%s/%d", baseUrl, ACCESS_TOKENS_ENDPOINT, accessTokenId);
  }

  @Override
  public String refreshTokenLocation(Long refreshTokenId) {
    return String.format("%s%s/%d", baseUrl, REFRESH_TOKENS_ENDPOINT, refreshTokenId);
  }

}
