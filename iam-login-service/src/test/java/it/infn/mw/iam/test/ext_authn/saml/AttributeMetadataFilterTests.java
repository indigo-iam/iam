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

import static it.infn.mw.iam.authn.saml.util.metadata.ResearchAndScholarshipMetadataFilter.ENTITY_CATEGORY_ATTRIBUTE_NAME;
import static it.infn.mw.iam.authn.saml.util.metadata.ResearchAndScholarshipMetadataFilter.R_S_ATTRIBUTE_VALUE;
import static it.infn.mw.iam.authn.saml.util.metadata.SirtfiAttributeMetadataFilter.ASSURANCE_CERTIFICATION_ATTRIBUTE_NAME;
import static it.infn.mw.iam.authn.saml.util.metadata.SirtfiAttributeMetadataFilter.SIRTFI_ATTRIBUTE_VALUE;
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.opensaml.saml2.core.Attribute.URI_REFERENCE;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.FilterException;
import org.opensaml.samlext.saml2mdattr.EntityAttributes;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;

import it.infn.mw.iam.authn.saml.util.metadata.SirtfiAttributeMetadataFilter;

@RunWith(MockitoJUnitRunner.class)
public class AttributeMetadataFilterTests {

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

  SirtfiAttributeMetadataFilter filter = new SirtfiAttributeMetadataFilter();

  protected Attribute buildMockAttribute(String name, String format, List<String> values) {
    Attribute attr = mock(Attribute.class);
    when(attr.getName()).thenReturn(name);
    when(attr.getNameFormat()).thenReturn(format);

    List<XMLObject> attributeValues = new ArrayList<>();

    values.forEach(s -> {
      XSString value = mock(XSString.class);
      when(value.getValue()).thenReturn(s);
      attributeValues.add(value);
    });

    when(attr.getAttributeValues()).thenReturn(attributeValues);
    return attr;
  }


  protected Extensions buildMockAttributeExtensions(EntityAttributes entityAttributes) {
    Extensions extensions = mock(Extensions.class);
    when(extensions.getUnknownXMLObjects(EntityAttributes.DEFAULT_ELEMENT_NAME))
      .thenReturn(asList(entityAttributes));
    return extensions;
  }


  protected EntityAttributes buildMockEntityAttributes(String attributeName, String attributeFormat,
      List<String> attributeValues) {

    EntityAttributes attrs = mock(EntityAttributes.class);
    List<Attribute> attrsAttrs = new ArrayList<>();
    attrsAttrs.add(buildMockAttribute(attributeName, attributeFormat, attributeValues));
    when(attrs.getAttributes()).thenReturn(attrsAttrs);

    return attrs;

  }

  @Before
  public void setup() {
    // when(entityDescriptor1.getEntityID()).thenReturn("1");
    when(entityDescriptor2.getEntityID()).thenReturn("2");
    when(entityDescriptor3.getEntityID()).thenReturn("3");
    when(entityDescriptor4.getEntityID()).thenReturn("4");

    EntityAttributes attrs1 = buildMockEntityAttributes(ASSURANCE_CERTIFICATION_ATTRIBUTE_NAME,
        Attribute.URI_REFERENCE, asList(SIRTFI_ATTRIBUTE_VALUE));

    Extensions extensions1 = buildMockAttributeExtensions(attrs1);
    when(entityDescriptor1.getExtensions()).thenReturn(extensions1);

    Extensions extensions2 = mock(Extensions.class);
    when(entityDescriptor2.getExtensions()).thenReturn(extensions2);

    EntityAttributes attrs3 = buildMockEntityAttributes(ASSURANCE_CERTIFICATION_ATTRIBUTE_NAME,
        Attribute.UNSPECIFIED, asList(SIRTFI_ATTRIBUTE_VALUE));

    Extensions extensions3 = buildMockAttributeExtensions(attrs3);
    when(entityDescriptor3.getExtensions()).thenReturn(extensions3);

    EntityAttributes attrs4 = buildMockEntityAttributes(ENTITY_CATEGORY_ATTRIBUTE_NAME,
        URI_REFERENCE, asList(R_S_ATTRIBUTE_VALUE));
    Extensions extensions4 = buildMockAttributeExtensions(attrs4);
    when(entityDescriptor4.getExtensions()).thenReturn(extensions4);

    when(entitiesDescriptor.getEntityDescriptors()).thenReturn(new ArrayList<>(
        Arrays.asList(entityDescriptor1, entityDescriptor2, entityDescriptor3, entityDescriptor4)));

  }

  @Test(expected = FilterException.class)
  public void testSirfiFilter() throws FilterException {

    try {
      filter.doFilter(entityDescriptor2);
    } catch (FilterException e) {
      assertThat(e.getMessage(),
          equalTo("Attribute 'urn:oasis:names:tc:SAML:attribute:assurance-certification' with "
              + "required values 'https://refeds.org/sirtfi' not found in EntityAttributes "
              + "for entity '2'"));
      throw e;
    }
  }

  @Test
  public void testSirfiFilterSuccess() throws FilterException {
    filter.doFilter(entityDescriptor1);
  }

  @Test
  public void testSirtfiEntities() throws FilterException {
    filter.doFilter(entitiesDescriptor);

    assertThat(entitiesDescriptor.getEntityDescriptors(), hasSize(1));
    assertThat(entitiesDescriptor.getEntityDescriptors(), hasItem(entityDescriptor1));
  }
}
