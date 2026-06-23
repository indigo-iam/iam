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
package it.infn.mw.iam.api.tokens.service.paging;

public record TokensPageRequest(int count, int startIndex) {

  public static final int TOKENS_MAX_PAGE_SIZE = 20;

  public static TokensPageRequest of(Integer count) {
    return of(count, 1);
  }

  public static TokensPageRequest of(Integer count, Integer startIndex) {
    boolean invalidCount = count == null || count > TOKENS_MAX_PAGE_SIZE || count < 0;
    boolean invalidStartIndex = startIndex == null || startIndex < 1;
    return new TokensPageRequest(invalidCount ? TOKENS_MAX_PAGE_SIZE : count,
        invalidStartIndex ? 1 : startIndex);
  }
}
