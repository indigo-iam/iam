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
package it.infn.mw.iam.config;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.CacheControl;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.resource.VersionResourceResolver;

@Component
@Profile("!h2-test")
public class VersionedResourceConfigurer implements ResourceHandlerConfigurer {

  @Value("${git.commit.id.abbrev}")
  private String gitCommit;

  @Override
  public void configure(ResourceHandlerRegistry registry) {
    registry.addResourceHandler("/resources/**")
      .addResourceLocations("/resources/")
      .setCacheControl(CacheControl.maxAge(30, TimeUnit.DAYS))
      .resourceChain(false)
      .addResolver(new VersionResourceResolver().addFixedVersionStrategy(gitCommit, "/**"));
  }
}
