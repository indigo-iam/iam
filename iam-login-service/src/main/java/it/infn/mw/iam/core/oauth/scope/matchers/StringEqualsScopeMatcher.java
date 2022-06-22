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
package it.infn.mw.iam.core.oauth.scope.matchers;

import javax.annotation.Generated;

public class StringEqualsScopeMatcher implements ScopeMatcher {

  final String expectedValue;

  private StringEqualsScopeMatcher(String expectedValue) {
    this.expectedValue = expectedValue;
  }

  @Override
  public boolean matches(String scope) {
    return expectedValue.equals(scope);
  }

  @Override
  @Generated("eclipse")
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((expectedValue == null) ? 0 : expectedValue.hashCode());
    return result;
  }

  @Override
  @Generated("eclipse")
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    StringEqualsScopeMatcher other = (StringEqualsScopeMatcher) obj;
    if (expectedValue == null) {
      if (other.expectedValue != null)
        return false;
    } else if (!expectedValue.equals(other.expectedValue))
      return false;
    return true;
  }
  
  public static StringEqualsScopeMatcher stringEqualsMatcher(String scope) {
    return new StringEqualsScopeMatcher(scope);
  }

}
