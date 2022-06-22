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
package it.infn.mw.iam.test.ext_authn.saml.profile;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import com.google.common.base.Joiner;
import com.google.common.collect.Lists;

import it.infn.mw.iam.authn.saml.DefaultMappingPropertiesResolver;
import it.infn.mw.iam.config.saml.IamSamlJITAccountProvisioningProperties.AttributeMappingProperties;
import it.infn.mw.iam.config.saml.IamSamlJITAccountProvisioningProperties.EntityAttributeMappingProperties;

@RunWith(MockitoJUnitRunner.class)
public class MappingPropertiesResolverTests {

  public static final String ENTITY_ID_1 = "urn:example:entityId1";
  public static final String ENTITY_ID_2 = "urn:example:entityId2";
  public static final String ENTITY_ID_3 = "urn:example:entityId3";

  AttributeMappingProperties defaultProperties = new AttributeMappingProperties();

  List<EntityAttributeMappingProperties> entityProperties = Lists.newArrayList();

  @Test
  public void testUnmatchedYeldsDefault() {

    DefaultMappingPropertiesResolver resolver =
        new DefaultMappingPropertiesResolver(defaultProperties, entityProperties);

    assertThat(resolver.resolveMappingProperties(ENTITY_ID_1), is(defaultProperties));
    assertThat(resolver.resolveMappingProperties(ENTITY_ID_2), is(defaultProperties));
  }

  @Test(expected = NullPointerException.class)
  public void testNullProperties() {

    try {
      new DefaultMappingPropertiesResolver(null, entityProperties);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), is("default properties cannot be null"));
      throw e;
    }
  }

  @Test(expected = NullPointerException.class)
  public void testNullProperties2() {

    try {
      new DefaultMappingPropertiesResolver(defaultProperties, null);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), is("entity properties cannot be null"));
      throw e;
    }
  }

  @Test
  public void testEntityMapping() {
    AttributeMappingProperties customMp = new AttributeMappingProperties();
    EntityAttributeMappingProperties entityMp = new EntityAttributeMappingProperties();
    entityMp.setEntityIds(ENTITY_ID_1);
    entityMp.setMapping(customMp);

    entityProperties.add(entityMp);

    DefaultMappingPropertiesResolver resolver =
        new DefaultMappingPropertiesResolver(defaultProperties, entityProperties);

    assertThat(resolver.resolveMappingProperties(ENTITY_ID_1), is(customMp));
    assertThat(resolver.resolveMappingProperties(ENTITY_ID_2), is(defaultProperties));
  }

  @Test
  public void testMultipleEntityMapping() {
    AttributeMappingProperties customMp = new AttributeMappingProperties();
    EntityAttributeMappingProperties entityMp = new EntityAttributeMappingProperties();
    entityMp.setEntityIds(Joiner.on(',').join(ENTITY_ID_1, ENTITY_ID_2));
    entityMp.setMapping(customMp);

    entityProperties.add(entityMp);

    DefaultMappingPropertiesResolver resolver =
        new DefaultMappingPropertiesResolver(defaultProperties, entityProperties);

    assertThat(resolver.resolveMappingProperties(ENTITY_ID_1), is(customMp));
    assertThat(resolver.resolveMappingProperties(ENTITY_ID_2), is(customMp));
    assertThat(resolver.resolveMappingProperties(ENTITY_ID_3), is(defaultProperties));
  }


}
