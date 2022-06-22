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
package it.infn.mw.iam.authn.saml.profile;

import static com.google.common.base.Preconditions.checkNotNull;
import static java.util.Objects.isNull;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;

import com.google.common.base.Splitter;
import com.google.common.collect.Maps;

import it.infn.mw.iam.config.saml.IamSamlProperties;
import it.infn.mw.iam.config.saml.IamSamlProperties.ProfileProperties;

public class DefaultSSOProfileOptionsResolver implements SSOProfileOptionsResolver {

  private final Map<String, IamSSOProfileOptions> optionsMap = Maps.newHashMap();
  private IamSSOProfileOptions defaultOptions;
  
  @Autowired
  public DefaultSSOProfileOptionsResolver(IamSamlProperties samlProperties, IamSSOProfileOptions defaultOptions) {
    checkNotNull(samlProperties, "samlProperties cannot be null");
    checkNotNull(defaultOptions, "defaultOptions cannot be null");
    this.defaultOptions = defaultOptions;
    if (!isNull(samlProperties.getCustomProfile())){
      samlProperties.getCustomProfile().forEach(this::addCustomProfileOptions);
    }
  }

  protected void addCustomProfileOptions(ProfileProperties properties) {
    if (!isNull(properties.getOptions())){
      for (String entityId : Splitter.on(',').omitEmptyStrings().split(properties.getEntityIds())) {
        optionsMap.put(entityId, properties.getOptions());
      }
    }
  }

  @Override
  public IamSSOProfileOptions resolveProfileOptions(String idpEntityId) {
    return optionsMap.getOrDefault(idpEntityId, defaultOptions); 
  }

}
