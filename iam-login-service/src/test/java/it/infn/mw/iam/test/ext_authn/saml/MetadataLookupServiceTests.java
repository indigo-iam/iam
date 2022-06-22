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
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNotNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
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

@RunWith(MockitoJUnitRunner.class)
public class MetadataLookupServiceTests {

  public static final String IDP1_ENTITY_ID = "urn:test:idp1";
  public static final String IDP2_ENTITY_ID = "urn:test:idp2";
  public static final String IDP3_ENTITY_ID = "urn:test:idp3";
  public static final String IDP4_ENTITY_ID = "urn:test:idp4";
  
  public static final String IDP1_ORGANIZATION_NAME = "IDP1 organization";
  public static final String IDP2_ORGANIZATION_NAME = "IDP2 organization";
  
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
  DisplayName idp1DisplayName, idp2DisplayName, idp4DisplayName;

  @Mock
  LocalizedString idp1LocalizedString, idp2LocalizedString, idp4LocalizedString;

  @Before
  public void setup() throws MetadataProviderException {

    when(idp1LocalizedString.getLocalString()).thenReturn(IDP1_ORGANIZATION_NAME);
    when(idp1DisplayName.getName()).thenReturn(idp1LocalizedString);
    when(idp1UIInfo.getDisplayNames()).thenReturn(asList(idp1DisplayName));

    when(idp2LocalizedString.getLocalString()).thenReturn(IDP2_ORGANIZATION_NAME);
    when(idp2DisplayName.getName()).thenReturn(idp2LocalizedString);
    when(idp2UIInfo.getDisplayNames()).thenReturn(asList(idp2DisplayName));

    when(idp4LocalizedString.getLocalString()).thenReturn("");
    when(idp4DisplayName.getName()).thenReturn(idp4LocalizedString);
    when(idp4UIInfo.getDisplayNames()).thenReturn(asList(idp4DisplayName));

    when(idp1SsoExtensions.getUnknownXMLObjects(UIInfo.DEFAULT_ELEMENT_NAME))
      .thenReturn(asList(idp1UIInfo));

    when(idp2SsoExtensions.getUnknownXMLObjects(UIInfo.DEFAULT_ELEMENT_NAME))
      .thenReturn(asList(idp2UIInfo));

    when(idp4SsoExtensions.getUnknownXMLObjects(UIInfo.DEFAULT_ELEMENT_NAME))
    .thenReturn(asList(idp4UIInfo));

    when(idp1SsoDesc.getExtensions()).thenReturn(idp1SsoExtensions);

    when(idp2SsoDesc.getExtensions()).thenReturn(idp2SsoExtensions);

    when(idp4SsoDesc.getExtensions()).thenReturn(idp4SsoExtensions);

    when(idp1Desc.getEntityID()).thenReturn(IDP1_ENTITY_ID);
    when(idp1Desc.getIDPSSODescriptor(SAMLConstants.SAML20P_NS)).thenReturn(idp1SsoDesc);

    when(idp2Desc.getEntityID()).thenReturn(IDP2_ENTITY_ID);
    when(idp2Desc.getIDPSSODescriptor(SAMLConstants.SAML20P_NS)).thenReturn(idp2SsoDesc);
    
    when(idp3Desc.getEntityID()).thenReturn(IDP3_ENTITY_ID);

    when(idp4Desc.getEntityID()).thenReturn(IDP4_ENTITY_ID);
    when(idp4Desc.getIDPSSODescriptor(SAMLConstants.SAML20P_NS)).thenReturn(idp4SsoDesc);

    when(manager.getEntityDescriptor(IDP1_ENTITY_ID)).thenReturn(idp1Desc);
    when(manager.getEntityDescriptor(IDP2_ENTITY_ID)).thenReturn(idp2Desc);
    when(manager.getEntityDescriptor(IDP3_ENTITY_ID)).thenReturn(idp3Desc);
    when(manager.getEntityDescriptor(IDP4_ENTITY_ID)).thenReturn(idp4Desc);

    when(manager.getIDPEntityNames()).thenReturn(Sets.newHashSet(IDP1_ENTITY_ID, IDP2_ENTITY_ID, 
        IDP3_ENTITY_ID, IDP4_ENTITY_ID));
  }


  @Test
  public void testServiceInitialization() throws MetadataProviderException {

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
        hasProperty("organizationName", is(IDP4_ENTITY_ID)))));
  }
  
  
  @Test
  public void testEmptyMetadataInitialization() {
    when(manager.getIDPEntityNames()).thenReturn(emptySet());
    DefaultMetadataLookupService service = new DefaultMetadataLookupService(manager);
    
    assertThat(service.listIdps(), hasSize(0));
  }
  
  @Test
  public void testLookupByOrganizationNameWorks() {
    DefaultMetadataLookupService service = new DefaultMetadataLookupService(manager);
    
    List<IdpDescription> idps = service.lookupIdp(IDP1_ORGANIZATION_NAME);
    assertThat(idps, hasSize(1));
    
    assertThat(idps, hasItem(allOf(hasProperty("entityId", is(IDP1_ENTITY_ID)),
        hasProperty("organizationName", is(IDP1_ORGANIZATION_NAME)))));
  }
  
  @Test
  public void testPartialLookupWorks() {
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
        hasProperty("organizationName", is(IDP4_ENTITY_ID)))));
  }
  
  @Test
  public void testEntityIdLookupWorks() {
   
    DefaultMetadataLookupService service = new DefaultMetadataLookupService(manager);
    List<IdpDescription> idps = service.lookupIdp(IDP1_ENTITY_ID);
    assertThat(idps, hasSize(1));
   
    assertThat(idps, hasItem(allOf(hasProperty("entityId", is(IDP1_ENTITY_ID)),
        hasProperty("organizationName", is(IDP1_ORGANIZATION_NAME)))));
    
    idps = service.lookupIdp("unknown");
    assertThat(idps, hasSize(0));
  }
}
