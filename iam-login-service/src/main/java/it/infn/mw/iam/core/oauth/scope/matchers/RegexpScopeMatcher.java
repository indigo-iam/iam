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

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Objects.nonNull;

import java.util.regex.Pattern;

import javax.annotation.Generated;

public class RegexpScopeMatcher implements ScopeMatcher {

  final String regexp;
  final Pattern pattern;

  protected RegexpScopeMatcher(String regexp) {
    this.regexp = regexp;
    pattern = Pattern.compile(regexp);
  }

  @Override
  public boolean matches(String scope) {
    checkArgument(nonNull(scope), "scope must be non-null");
    return pattern.matcher(scope).matches();
  }

  public static RegexpScopeMatcher regexpMatcher(String regexp) {
    return new RegexpScopeMatcher(regexp);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((regexp == null) ? 0 : regexp.hashCode());
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
    RegexpScopeMatcher other = (RegexpScopeMatcher) obj;
    if (regexp == null) {
      if (other.regexp != null)
        return false;
    } else if (!regexp.equals(other.regexp))
      return false;
    return true;
  }

}
