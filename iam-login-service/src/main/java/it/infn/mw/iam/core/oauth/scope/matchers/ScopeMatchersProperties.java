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

import java.util.List;

import javax.validation.Valid;

import javax.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import com.google.common.collect.Lists;

@Configuration
@ConfigurationProperties(prefix = "scope")
@Validated
public class ScopeMatchersProperties {

  public static class MatcherProperties {
    public enum MatcherType {
      regexp,
      path
    }

    @NotBlank
    String name;

    MatcherType type;

    String regexp;

    String prefix;
    String path;


    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public MatcherType getType() {
      return type;
    }

    public void setType(MatcherType type) {
      this.type = type;
    }

    public String getRegexp() {
      return regexp;
    }

    public void setRegexp(String regexp) {
      this.regexp = regexp;
    }

    public String getPrefix() {
      return prefix;
    }

    public void setPrefix(String prefix) {
      this.prefix = prefix;
    }

    public String getPath() {
      return path;
    }

    public void setPath(String path) {
      this.path = path;
    }
  }

  @Valid
  List<MatcherProperties> matchers = Lists.newArrayList();

  public List<MatcherProperties> getMatchers() {
    return matchers;
  }

  public void setMatchers(List<MatcherProperties> matchers) {
    this.matchers = matchers;
  }

}
