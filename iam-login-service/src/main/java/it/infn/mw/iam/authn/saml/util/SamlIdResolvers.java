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
package it.infn.mw.iam.authn.saml.util;

import static it.infn.mw.iam.authn.saml.util.NameIdUserIdentifierResolver.NAMEID_RESOLVER;
import static it.infn.mw.iam.authn.saml.util.PersistentNameIdUserIdentifierResolver.PERSISTENT_NAMEID_RESOLVER;
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.EPTID;

import java.util.EnumSet;
import java.util.Map;

import com.google.common.collect.ImmutableMap;

public class SamlIdResolvers {

  private Map<String, NamedSamlUserIdentifierResolver> registeredResolvers;

  public SamlIdResolvers() {
    ImmutableMap.Builder<String, NamedSamlUserIdentifierResolver> builder =
        ImmutableMap.<String, NamedSamlUserIdentifierResolver>builder();

    for (Saml2Attribute a: EnumSet.complementOf(EnumSet.of(EPTID))) {
      builder.put(a.getAlias(), new AttributeUserIdentifierResolver(a));
    }

    // EPTID has its own resolver 
    builder.put(EPTID.getAlias(), new EPTIDUserIdentifierResolver());
    builder.put(PERSISTENT_NAMEID_RESOLVER, new PersistentNameIdUserIdentifierResolver());
    builder.put(NAMEID_RESOLVER, new NameIdUserIdentifierResolver());

    registeredResolvers = builder.build();
  }

  public NamedSamlUserIdentifierResolver byAttribute(Saml2Attribute attribute) {
    return registeredResolvers.get(attribute.getAlias());
  }

  public NamedSamlUserIdentifierResolver byName(String name) {
    return registeredResolvers.get(name);
  }


}
