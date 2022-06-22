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
package it.infn.mw.iam.authn.saml.util.metadata;

import static it.infn.mw.iam.authn.saml.util.metadata.ValidationResult.invalid;
import static it.infn.mw.iam.authn.saml.util.metadata.ValidationResult.valid;
import static java.lang.String.format;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.samlext.saml2mdattr.EntityAttributes;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;

public class AttributeValueMetadataFilter extends AbstractMetadataFilter {

  private final String attributeName;
  private final String attributeNameFormat;
  private final List<String> requiredValues;

  public AttributeValueMetadataFilter(String attributeName, String attributeNameFormat,
      List<String> requiredValues) {
    this.attributeName = attributeName;
    this.attributeNameFormat = attributeNameFormat;
    this.requiredValues = requiredValues;
  }

  public AttributeValueMetadataFilter(String attributeName, List<String> requiredValues) {
    this(attributeName, Attribute.URI_REFERENCE, requiredValues);
  }

  private String join(List<String> list) {
    return list.stream().collect(Collectors.joining(","));
  }

  private String getXsStringAttributeValue(XSString string) {
    return string.getValue();
  }

  private String getXsAnyAttributeValue(XSAny any) {
    return any.getTextContent();
  }

  // This function explains why people hate opensaml
  private String getAttributeValue(XMLObject object) {
    if (object instanceof XSString) {
      return getXsStringAttributeValue((XSString) object);
    }
    if (object instanceof XSAny) {
      return getXsAnyAttributeValue((XSAny) object);
    }
    return null;
  }

  protected Optional<ValidationResult> checkEntityAttributes(EntityAttributes attributes) {

    for (Attribute attr : attributes.getAttributes()) {
      if (attributeName.equals(attr.getName())
          && attributeNameFormat.equals(attr.getNameFormat())) {
        return Optional.of(checkAttributeValues(attr));
      }
    }
    
    return Optional.empty();

  }

  protected ValidationResult checkAttributeValues(Attribute attribute) {
    List<String> attributeValues = attribute.getAttributeValues()
      .stream()
      .map(this::getAttributeValue)
      .filter(Objects::nonNull)
      .collect(Collectors.toList());

    if (attributeValues.containsAll(requiredValues)) {
      return valid();
    }

    return invalid(format("Attribute '%s' has values '%s'. Required values: '%s'", attributeName,
        join(attributeValues), join(requiredValues)));
  }

  @Override
  protected ValidationResult validateEntityDescriptor(EntityDescriptor descriptor) {
    if (descriptor.getExtensions() == null) {
      return invalid(format("No extensions present for descriptor '%s'", descriptor.getEntityID()));
    }

    for (final XMLObject object : descriptor.getExtensions()
      .getUnknownXMLObjects(EntityAttributes.DEFAULT_ELEMENT_NAME)) {
      
      Optional<ValidationResult> result = checkEntityAttributes((EntityAttributes) object);
      
      if (result.isPresent()){
        return result.get();
      }
    }

    return invalid(String.format(
        "Attribute '%s' with required values '%s' not found in EntityAttributes for entity '%s'",
        attributeName, join(requiredValues), descriptor.getEntityID()));
  }

}
