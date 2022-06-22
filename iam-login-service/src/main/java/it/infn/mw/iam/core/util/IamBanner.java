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
package it.infn.mw.iam.core.util;

import java.io.IOException;
import java.util.List;

import org.springframework.boot.ResourceBanner;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertyResolver;
import org.springframework.core.env.PropertySourcesPropertyResolver;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.ResourcePropertySource;

import it.infn.mw.iam.core.error.StartupError;


public class IamBanner extends ResourceBanner {

  public IamBanner(Resource resource) {
    super(resource);
  }


  protected PropertyResolver getIamInfoPropertyResolver() throws IOException {

    MutablePropertySources sources = new MutablePropertySources();

    ResourcePropertySource iamVersionProps =
        new ResourcePropertySource(new ClassPathResource("iam.version.properties"));
    ResourcePropertySource gitCommitProps =
        new ResourcePropertySource(new ClassPathResource("git.properties"));
    sources.addLast(iamVersionProps);
    sources.addLast(gitCommitProps);


    return new PropertySourcesPropertyResolver(sources);

  }

  @Override
  protected List<PropertyResolver> getPropertyResolvers(Environment environment,
      Class<?> sourceClass) {

    List<PropertyResolver> resolvers = super.getPropertyResolvers(environment, sourceClass);

    try {
      resolvers.add(getIamInfoPropertyResolver());
    } catch (IOException e) {
      throw new StartupError("Error initializing banner property resolvers", e);
    }
    return resolvers;
  }

}
