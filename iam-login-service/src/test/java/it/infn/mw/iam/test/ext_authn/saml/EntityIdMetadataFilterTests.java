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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.FilterException;
import org.opensaml.xml.XMLObject;

import it.infn.mw.iam.authn.saml.util.metadata.AbstractMetadataFilter;
import it.infn.mw.iam.authn.saml.util.metadata.EntityIdWhitelistMetadataFilter;

@RunWith(MockitoJUnitRunner.class)
public class EntityIdMetadataFilterTests {

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

  @Before
  public void setup() {
    when(entityDescriptor1.getEntityID()).thenReturn("1");
    when(entityDescriptor2.getEntityID()).thenReturn("2");
    when(entityDescriptor3.getEntityID()).thenReturn("3");
    when(entityDescriptor4.getEntityID()).thenReturn("4");

    when(entitiesDescriptor.getEntityDescriptors())
      .thenReturn(new ArrayList<>(Arrays.asList(entityDescriptor1, entityDescriptor2)));

    when(childEntitiesDescriptor.getEntityDescriptors())
      .thenReturn(new ArrayList<>(Arrays.asList(entityDescriptor3, entityDescriptor4)));

    when(entitiesDescriptor.getEntitiesDescriptors())
      .thenReturn(new ArrayList<>(asList(childEntitiesDescriptor)));

    when(entitiesDescriptor.getEntityDescriptors())
      .thenReturn(new ArrayList<>(Arrays.asList(entityDescriptor1, entityDescriptor2)));
  }


  @Test(expected = FilterException.class)
  public void wrongTypeMetadataFilterTest() throws FilterException {
    filter = new EntityIdWhitelistMetadataFilter(emptyList());

    XMLObject baseObject = mock(XMLObject.class);
    try {
      filter.doFilter(baseObject);
    } catch (FilterException e) {
      assertThat(e.getMessage(),
          equalTo("XMLObject is not a EntityDescriptor or and EntitiesDescriptor"));
      throw e;
    }
  }

  @Test(expected = FilterException.class)
  public void nullMetadataFilterTest() throws FilterException {
    filter = new EntityIdWhitelistMetadataFilter(emptyList());

    try {
      filter.doFilter(null);
    } catch (FilterException e) {
      assertThat(e.getMessage(), equalTo("Cannot filter null metadata"));
      throw e;
    }
  }

  @Test(expected = FilterException.class)
  public void singleEntityDescriptorFilterTest() throws FilterException {
    filter = new EntityIdWhitelistMetadataFilter(emptyList());

    try {
      filter.doFilter(entityDescriptor1);
    } catch (FilterException e) {
      assertThat(e.getMessage(), startsWith("Entity id '1' not found in whitelist"));
      throw e;
    }

  }
  
  @Test
  public void singleEntityDescriptorFilterPassTest() throws FilterException {
    filter = new EntityIdWhitelistMetadataFilter(asList("1"));
    filter.doFilter(entityDescriptor1);
  }

  @Test
  public void multipleEntityDescriptorsFilterTest() throws FilterException {
    filter = new EntityIdWhitelistMetadataFilter(asList("1"));

    filter.doFilter(entitiesDescriptor);
    assertThat(entitiesDescriptor.getEntityDescriptors(), hasSize(1));
    assertThat(entitiesDescriptor.getEntityDescriptors(), hasItem(entityDescriptor1));
    assertThat(entitiesDescriptor.getEntitiesDescriptors(), hasSize(0));

  }

  @Test
  public void multipleEntityDescriptorsFilterTest2() throws FilterException {
    filter = new EntityIdWhitelistMetadataFilter(asList("1", "3"));

    filter.doFilter(entitiesDescriptor);
    assertThat(entitiesDescriptor.getEntityDescriptors(), hasSize(1));
    assertThat(entitiesDescriptor.getEntityDescriptors(), hasItem(entityDescriptor1));
    assertThat(entitiesDescriptor.getEntitiesDescriptors(), hasSize(1));
    assertThat(entitiesDescriptor.getEntitiesDescriptors().get(0).getEntityDescriptors(),
        hasSize(1));
    assertThat(entitiesDescriptor.getEntitiesDescriptors().get(0).getEntityDescriptors(),
        hasItem(entityDescriptor3));

  }

  @Test
  public void multipleEntityDescriptorsFilterNoChildEntitiesTest() throws FilterException {
    filter = new EntityIdWhitelistMetadataFilter(asList("1"));
    when(entitiesDescriptor.getEntitiesDescriptors()).thenReturn(null);
    filter.doFilter(entitiesDescriptor);
    assertThat(entitiesDescriptor.getEntityDescriptors(), hasSize(1));
  }

  @Test
  public void entityFilterCanHandleNullEntityDescriptors() throws FilterException {

    filter = new EntityIdWhitelistMetadataFilter(asList("1"));
    when(entitiesDescriptor.getEntityDescriptors()).thenReturn(null);

    filter.doFilter(entitiesDescriptor);
    
  }

}
