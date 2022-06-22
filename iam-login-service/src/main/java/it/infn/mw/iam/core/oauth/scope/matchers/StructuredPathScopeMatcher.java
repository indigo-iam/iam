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
import static com.google.common.base.Strings.isNullOrEmpty;
import static java.util.Objects.nonNull;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.Generated;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StructuredPathScopeMatcher implements ScopeMatcher {

  public static final Logger LOG = LoggerFactory.getLogger(StructuredPathScopeMatcher.class);

  private static final Pattern POINT_DIR_MATCHER = Pattern.compile("\\.\\./?");
  
  private static final Character SEP = ':';
  private static final String SEP_STR = SEP.toString();

  private final String prefix;
  private final String path;

  private final Pattern prefixMatchPattern;
  private final Pattern pathMatchPattern;

  private StructuredPathScopeMatcher(String prefix, String path) {

    this.prefix = prefix;
    this.path = path;

    final String prefixMatchRegexp = String.format("^%s%c", prefix, SEP);
    prefixMatchPattern = Pattern.compile(prefixMatchRegexp);
    pathMatchPattern = Pattern.compile(path + ".*");
  }

  @Override
  public boolean matches(String scope) {
    checkArgument(nonNull(scope), "scope must be non-null");

    if (POINT_DIR_MATCHER.matcher(scope).find()) {
      throw new IllegalArgumentException("Scope contains relative path references");
    }

    Matcher prefixMatcher = prefixMatchPattern.matcher(scope);
    
    boolean prefixMatches = prefixMatcher.find();
    
    if (prefixMatches) {
      final String scopePath = scope.substring(prefix.length() + 1);
      return pathMatchPattern.matcher(scopePath).matches(); 
    } else {
      return false;
    }
  }
  
  public static StructuredPathScopeMatcher fromString(String scope) {
    final int sepIndex = scope.indexOf(SEP);
    final String prefix = scope.substring(0, sepIndex);
    final String path = scope.substring(sepIndex+1, scope.length());
    return new StructuredPathScopeMatcher(prefix, path);
  }

  public static StructuredPathScopeMatcher structuredPathMatcher(String prefix, String path) {
    checkArgument(!isNullOrEmpty(prefix), "empty or null prefix");
    checkArgument(!prefix.contains(SEP_STR), "prefix must not contain context separator");
    checkArgument(!isNullOrEmpty(path), "empty or null path");
    checkArgument(path.startsWith("/"), "path must start with a /");

    return new StructuredPathScopeMatcher(prefix, path);
  }

  @Override
  public String toString() {
    return String.format("%s:%s", prefix, path);
  }

  @Override
  @Generated("eclipse")
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((path == null) ? 0 : path.hashCode());
    result = prime * result + ((prefix == null) ? 0 : prefix.hashCode());
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
    StructuredPathScopeMatcher other = (StructuredPathScopeMatcher) obj;
    if (path == null) {
      if (other.path != null)
        return false;
    } else if (!path.equals(other.path))
      return false;
    if (prefix == null) {
      if (other.prefix != null)
        return false;
    } else if (!prefix.equals(other.prefix))
      return false;
    return true;
  }

  public String getPrefix() {
    return prefix;
  }

  public String getPath() {
    return path;
  }
  
}
