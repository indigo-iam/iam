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
package it.infn.mw.iam.core.oauth.attributes;

import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Component;

import com.google.common.collect.Maps;

import it.infn.mw.iam.persistence.model.IamAttribute;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@Component
public class AttributeMapHelper {

  public static final String ATTR_SCOPE = "attr";

  public Map<String, String> getAttributeMapFromUserInfo(IamUserInfo info) {

    Map<String, String> result = Maps.newHashMap();

    Set<IamAttribute> attrs = info.getIamAccount().getAttributes();

    for (IamAttribute a : attrs) {
      result.put(a.getName(), a.getValue());
    }

    return result;
  }

}
