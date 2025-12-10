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
package it.infn.mw.iam.test.ext_authn.saml;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.FilterException;
import org.opensaml.xml.XMLObject;

import it.infn.mw.iam.authn.saml.util.metadata.AbstractMetadataFilter;
import it.infn.mw.iam.authn.saml.util.metadata.EntityIdWhitelistMetadataFilter;

@ExtendWith(MockitoExtension.class)
class EntityIdMetadataFilterTests {

  @Mock
  EntityDescriptor entityDescriptor1;

  @Mock
  EntityDescriptor entityDescriptor2;

  @Mock
  EntityDescriptor entityDescriptor3;

  @Mock
  EntityDescriptor entityDescriptor4;

  @Mock
  EntitiesDescriptor entitiesDescriptor;

  @Mock
  EntitiesDescriptor childEntitiesDescriptor;

  XMLObject metadata;

  AbstractMetadataFilter filter;

  @BeforeEach
  void setup() {

    lenient().when(entityDescriptor1.getEntityID()).thenReturn("1");
    lenient().when(entityDescriptor2.getEntityID()).thenReturn("2");
    lenient().when(entityDescriptor3.getEntityID()).thenReturn("3");
    lenient().when(entityDescriptor4.getEntityID()).thenReturn("4");

    lenient().when(entitiesDescriptor.getEntityDescriptors())
      .thenReturn(new ArrayList<>(Arrays.asList(entityDescriptor1, entityDescriptor2)));

    lenient().when(childEntitiesDescriptor.getEntityDescriptors())
      .thenReturn(new ArrayList<>(Arrays.asList(entityDescriptor3, entityDescriptor4)));

    lenient().when(entitiesDescriptor.getEntitiesDescriptors())
      .thenReturn(new ArrayList<>(asList(childEntitiesDescriptor)));

    lenient().when(entitiesDescriptor.getEntityDescriptors())
      .thenReturn(new ArrayList<>(Arrays.asList(entityDescriptor1, entityDescriptor2)));
  }

  @Test
  void wrongTypeMetadataFilterTest() {

    filter = new EntityIdWhitelistMetadataFilter(emptyList());
    XMLObject baseObject = mock(XMLObject.class);
    FilterException e = assertThrows(FilterException.class, () -> filter.doFilter(baseObject));
    assertThat(e.getMessage(),
        equalTo("XMLObject is not a EntityDescriptor or and EntitiesDescriptor"));
  }

  @Test
  void nullMetadataFilterTest() {

    filter = new EntityIdWhitelistMetadataFilter(emptyList());
    FilterException e = assertThrows(FilterException.class, () -> filter.doFilter(null));
    assertThat(e.getMessage(), equalTo("Cannot filter null metadata"));
  }

  @Test
  void singleEntityDescriptorFilterTest() {

    filter = new EntityIdWhitelistMetadataFilter(emptyList());
    FilterException e =
        assertThrows(FilterException.class, () -> filter.doFilter(entityDescriptor1));
    assertThat(e.getMessage(), startsWith("Entity id '1' not found in whitelist"));
  }

  @Test
  void singleEntityDescriptorFilterPassTest() {
    filter = new EntityIdWhitelistMetadataFilter(asList("1"));
    assertDoesNotThrow(() -> filter.doFilter(entityDescriptor1));
  }

  @Test
  void multipleEntityDescriptorsFilterTest() {
    filter = new EntityIdWhitelistMetadataFilter(asList("1"));

    assertDoesNotThrow(() -> filter.doFilter(entitiesDescriptor));
    assertThat(entitiesDescriptor.getEntityDescriptors(), hasSize(1));
    assertThat(entitiesDescriptor.getEntityDescriptors(), hasItem(entityDescriptor1));
    assertThat(entitiesDescriptor.getEntitiesDescriptors(), hasSize(0));
  }

  @Test
  void multipleEntityDescriptorsFilterTest2() {

    filter = new EntityIdWhitelistMetadataFilter(asList("1", "3"));

    assertDoesNotThrow(() -> filter.doFilter(entitiesDescriptor));
    assertThat(entitiesDescriptor.getEntityDescriptors(), hasSize(1));
    assertThat(entitiesDescriptor.getEntityDescriptors(), hasItem(entityDescriptor1));
    assertThat(entitiesDescriptor.getEntitiesDescriptors(), hasSize(1));
    assertThat(entitiesDescriptor.getEntitiesDescriptors().get(0).getEntityDescriptors(),
        hasSize(1));
    assertThat(entitiesDescriptor.getEntitiesDescriptors().get(0).getEntityDescriptors(),
        hasItem(entityDescriptor3));
  }

  @Test
  void multipleEntityDescriptorsFilterNoChildEntitiesTest() {

    filter = new EntityIdWhitelistMetadataFilter(asList("1"));
    lenient().when(entitiesDescriptor.getEntitiesDescriptors()).thenReturn(null);
    assertDoesNotThrow(() -> filter.doFilter(entitiesDescriptor));
    assertThat(entitiesDescriptor.getEntityDescriptors(), hasSize(1));
  }

  @Test
  void entityFilterCanHandleNullEntityDescriptors() {

    filter = new EntityIdWhitelistMetadataFilter(asList("1"));
    lenient().when(entitiesDescriptor.getEntityDescriptors()).thenReturn(null);

    assertDoesNotThrow(() -> filter.doFilter(entitiesDescriptor));
  }
}
