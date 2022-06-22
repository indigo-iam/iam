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
package it.infn.mw.iam.test.api.tokens;

import static java.util.Collections.singletonList;

import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.google.common.collect.Lists;

public class MultiValueMapBuilder {

  private MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();

  public static MultiValueMapBuilder builder() {

    return new MultiValueMapBuilder();
  }

  public MultiValueMapBuilder count(long count) {

    params.put("count", Lists.newArrayList(String.valueOf(count)));
    return this;
  }

  public MultiValueMapBuilder startIndex(long startIndex) {

    params.put("startIndex", Lists.newArrayList(String.valueOf(startIndex)));
    return this;
  }

  public MultiValueMapBuilder userId(String userId) {

    params.put("userId", Lists.newArrayList(userId));
    return this;
  }

  public MultiValueMapBuilder clientId(String clientId) {

    params.put("clientId", Lists.newArrayList(clientId));
    return this;
  }

  public MultiValueMapBuilder attributes(String value) {

    params.put("attributes", Lists.newArrayList(value));
    return this;
  }

  public MultiValueMapBuilder singleStringParam(String paramName, String paramValue) {
    params.put(paramName, singletonList(paramValue));
    return this;
  }


  public MultiValueMap<String, String> build() {
    return params;
  }
}
