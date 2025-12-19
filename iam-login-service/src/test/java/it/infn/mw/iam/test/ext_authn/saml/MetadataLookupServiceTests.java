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
import static java.util.Collections.emptySet;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.lenient;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.LocalizedString;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.samlext.saml2mdui.DisplayName;
import org.opensaml.samlext.saml2mdui.UIInfo;
import org.springframework.security.saml.metadata.MetadataManager;

import com.google.common.collect.Sets;

import it.infn.mw.iam.authn.saml.DefaultMetadataLookupService;
import it.infn.mw.iam.authn.saml.model.IdpDescription;

@ExtendWith(MockitoExtension.class)
class MetadataLookupServiceTests {

  static final String IDP1_ENTITY_ID = "urn:test:idp1";
  static final String IDP2_ENTITY_ID = "urn:test:idp2";
  static final String IDP3_ENTITY_ID = "urn:test:idp3";
  static final String IDP4_ENTITY_ID = "urn:test:idp4";

  static final String IDP1_ORGANIZATION_NAME = "IDP1 organization";
  static final String IDP2_ORGANIZATION_NAME = "IDP2 organization";
  static final String IDP4_ORGANIZATION_NAME = "IDP4 organization";

  @Mock
  MetadataManager manager;

  @Mock
  EntityDescriptor idp1Desc, idp2Desc, idp3Desc, idp4Desc;

  @Mock
  IDPSSODescriptor idp1SsoDesc, idp2SsoDesc, idp4SsoDesc;

  @Mock
  Extensions idp1SsoExtensions, idp2SsoExtensions, idp4SsoExtensions;

  @Mock
  UIInfo idp1UIInfo, idp2UIInfo, idp4UIInfo;

  @Mock
  DisplayName idp1DisplayName, idp1ItDisplayName, idp2DisplayName, idp4DisplayName;

  @Mock
  LocalizedString idp1LocalizedString, idp1ItLocalizedString, idp2LocalizedString,
      idp4LocalizedString;

  @BeforeEach
  void setup() throws MetadataProviderException {

    lenient().when(idp1LocalizedString.getLocalString()).thenReturn(IDP1_ORGANIZATION_NAME);
    lenient().when(idp1ItLocalizedString.getLocalString()).thenReturn("IDP1 organizzazione");
    lenient().when(idp1DisplayName.getName()).thenReturn(idp1LocalizedString);
    lenient().when(idp1ItDisplayName.getName()).thenReturn(idp1ItLocalizedString);
    lenient().when(idp1UIInfo.getDisplayNames())
      .thenReturn(asList(idp1DisplayName, idp1ItDisplayName));

    lenient().when(idp2LocalizedString.getLocalString()).thenReturn(IDP2_ORGANIZATION_NAME);
    lenient().when(idp2DisplayName.getName()).thenReturn(idp2LocalizedString);
    lenient().when(idp2UIInfo.getDisplayNames()).thenReturn(asList(idp2DisplayName));

    lenient().when(idp4LocalizedString.getLocalString()).thenReturn(IDP4_ORGANIZATION_NAME);
    lenient().when(idp4DisplayName.getName()).thenReturn(idp4LocalizedString);
    lenient().when(idp4UIInfo.getDisplayNames()).thenReturn(asList(idp4DisplayName));

    lenient().when(idp1SsoExtensions.getUnknownXMLObjects(UIInfo.DEFAULT_ELEMENT_NAME))
      .thenReturn(asList(idp1UIInfo));

    lenient().when(idp2SsoExtensions.getUnknownXMLObjects(UIInfo.DEFAULT_ELEMENT_NAME))
      .thenReturn(asList(idp2UIInfo));

    lenient().when(idp4SsoExtensions.getUnknownXMLObjects(UIInfo.DEFAULT_ELEMENT_NAME))
      .thenReturn(asList(idp4UIInfo));

    lenient().when(idp1SsoDesc.getExtensions()).thenReturn(idp1SsoExtensions);

    lenient().when(idp2SsoDesc.getExtensions()).thenReturn(idp2SsoExtensions);

    lenient().when(idp4SsoDesc.getExtensions()).thenReturn(idp4SsoExtensions);

    lenient().when(idp1Desc.getEntityID()).thenReturn(IDP1_ENTITY_ID);
    lenient().when(idp1Desc.getIDPSSODescriptor(SAMLConstants.SAML20P_NS)).thenReturn(idp1SsoDesc);

    lenient().when(idp2Desc.getEntityID()).thenReturn(IDP2_ENTITY_ID);
    lenient().when(idp2Desc.getIDPSSODescriptor(SAMLConstants.SAML20P_NS)).thenReturn(idp2SsoDesc);

    lenient().when(idp3Desc.getEntityID()).thenReturn(IDP3_ENTITY_ID);

    lenient().when(idp4Desc.getEntityID()).thenReturn(IDP4_ENTITY_ID);
    lenient().when(idp4Desc.getIDPSSODescriptor(SAMLConstants.SAML20P_NS)).thenReturn(idp4SsoDesc);

    lenient().when(manager.getEntityDescriptor(IDP1_ENTITY_ID)).thenReturn(idp1Desc);
    lenient().when(manager.getEntityDescriptor(IDP2_ENTITY_ID)).thenReturn(idp2Desc);
    lenient().when(manager.getEntityDescriptor(IDP3_ENTITY_ID)).thenReturn(idp3Desc);
    lenient().when(manager.getEntityDescriptor(IDP4_ENTITY_ID)).thenReturn(idp4Desc);

    lenient().when(manager.getIDPEntityNames())
      .thenReturn(Sets.newHashSet(IDP1_ENTITY_ID, IDP2_ENTITY_ID, IDP3_ENTITY_ID, IDP4_ENTITY_ID));
  }

  @Test
  void testServiceInitialization() {

    DefaultMetadataLookupService service = new DefaultMetadataLookupService(manager);

    assertNotNull(service.listIdps());
    List<IdpDescription> idps = service.listIdps();

    assertThat(idps, hasSize(4));

    assertThat(idps, hasItem(allOf(hasProperty("entityId", is(IDP1_ENTITY_ID)),
        hasProperty("organizationName", is(IDP1_ORGANIZATION_NAME)))));

    assertThat(idps, hasItem(allOf(hasProperty("entityId", is(IDP2_ENTITY_ID)),
        hasProperty("organizationName", is(IDP2_ORGANIZATION_NAME)))));

    assertThat(idps, hasItem(allOf(hasProperty("entityId", is(IDP3_ENTITY_ID)),
        hasProperty("organizationName", is(IDP3_ENTITY_ID)))));

    assertThat(idps, hasItem(allOf(hasProperty("entityId", is(IDP4_ENTITY_ID)),
        hasProperty("organizationName", is(IDP4_ORGANIZATION_NAME)))));
  }


  @Test
  void testEmptyMetadataInitialization() {
    lenient().when(manager.getIDPEntityNames()).thenReturn(emptySet());
    DefaultMetadataLookupService service = new DefaultMetadataLookupService(manager);

    assertThat(service.listIdps(), hasSize(0));
  }

  @Test
  void testEmptyTextToFind() {
    DefaultMetadataLookupService service = new DefaultMetadataLookupService(manager);

    List<IdpDescription> idps = service.lookupIdp("noMatchOnTextToFind");
    assertThat(idps, hasSize(0));
  }

  @Test
  void testLookupByOrganizationNameWorks() {
    DefaultMetadataLookupService service = new DefaultMetadataLookupService(manager);

    List<IdpDescription> idpsIt = service.lookupIdp("organizz");
    assertThat(idpsIt, hasSize(1));

    assertThat(idpsIt, hasItem(allOf(hasProperty("entityId", is(IDP1_ENTITY_ID)),
        hasProperty("organizationName", is("IDP1 organizzazione")))));

    List<IdpDescription> idpsEn = service.lookupIdp(IDP1_ORGANIZATION_NAME);
    assertThat(idpsEn, hasSize(1));

    assertThat(idpsEn, hasItem(allOf(hasProperty("entityId", is(IDP1_ENTITY_ID)),
        hasProperty("organizationName", is(IDP1_ORGANIZATION_NAME)))));
  }

  @Test
  void testPartialLookupWorks() {
    DefaultMetadataLookupService service = new DefaultMetadataLookupService(manager);

    List<IdpDescription> idps = service.lookupIdp("idp");
    assertThat(idps, hasSize(4));

    assertThat(idps, hasItem(allOf(hasProperty("entityId", is(IDP1_ENTITY_ID)),
        hasProperty("organizationName", is(IDP1_ORGANIZATION_NAME)))));

    assertThat(idps, hasItem(allOf(hasProperty("entityId", is(IDP2_ENTITY_ID)),
        hasProperty("organizationName", is(IDP2_ORGANIZATION_NAME)))));

    assertThat(idps, hasItem(allOf(hasProperty("entityId", is(IDP3_ENTITY_ID)),
        hasProperty("organizationName", is(IDP3_ENTITY_ID)))));

    assertThat(idps, hasItem(allOf(hasProperty("entityId", is(IDP4_ENTITY_ID)),
        hasProperty("organizationName", is(IDP4_ORGANIZATION_NAME)))));
  }

  @Test
  void testEntityIdLookupWorks() {

    DefaultMetadataLookupService service = new DefaultMetadataLookupService(manager);
    List<IdpDescription> idps = service.lookupIdp(IDP1_ENTITY_ID);
    assertThat(idps, hasSize(1));

    assertThat(idps, hasItem(allOf(hasProperty("entityId", is(IDP1_ENTITY_ID)),
        hasProperty("organizationName", is(IDP1_ORGANIZATION_NAME)))));

    idps = service.lookupIdp("unknown");
    assertThat(idps, hasSize(0));
  }
}
