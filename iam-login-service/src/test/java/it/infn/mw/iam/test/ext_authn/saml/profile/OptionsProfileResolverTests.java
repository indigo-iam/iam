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
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import com.google.common.base.Joiner;
import com.google.common.collect.Lists;

import it.infn.mw.iam.authn.saml.profile.DefaultSSOProfileOptionsResolver;
import it.infn.mw.iam.authn.saml.profile.IamSSOProfileOptions;
import it.infn.mw.iam.config.saml.IamSamlProperties;
import it.infn.mw.iam.config.saml.IamSamlProperties.ProfileProperties;

@RunWith(MockitoJUnitRunner.class)
public class OptionsProfileResolverTests {

  public static final String ENTITY_ID_1 = "urn:example:entityId1";
  public static final String ENTITY_ID_2 = "urn:example:entityId2";

  @Mock
  IamSamlProperties properties;

  @Mock
  IamSSOProfileOptions defaultOptions;

  @Mock
  ProfileProperties pp;

  
  @Test(expected = NullPointerException.class)
  public void testNullChecks1() {
    
    try {
        new DefaultSSOProfileOptionsResolver(null, defaultOptions);
    }catch(NullPointerException e) {
      assertThat(e.getMessage(), is("samlProperties cannot be null"));
      throw e;
    }
  }
  
  @Test(expected = NullPointerException.class)
  public void testNullChecks2() {
    
    try {
      new DefaultSSOProfileOptionsResolver(properties, null);
    }catch(NullPointerException e) {
      assertThat(e.getMessage(), is("defaultOptions cannot be null"));
      throw e;
    }
  }
  @Test
  public void testUnmatchedProfileYeldsDefaultProfile() {

    DefaultSSOProfileOptionsResolver resolver =
        new DefaultSSOProfileOptionsResolver(properties, defaultOptions);

    IamSSOProfileOptions options = resolver.resolveProfileOptions(ENTITY_ID_1);
    assertThat(options, is(defaultOptions));
  }


  @Test
  public void testSingleEntityCustomProfileResolution() {
    
    IamSSOProfileOptions customOpts = new IamSSOProfileOptions();
    customOpts.setSpidIdp(true);
    customOpts.setPassive(null);
    
    when(pp.getEntityIds()).thenReturn(ENTITY_ID_1);
    when(pp.getOptions()).thenReturn(customOpts);
    
    when(properties.getCustomProfile()).thenReturn(Lists.newArrayList(pp));

    DefaultSSOProfileOptionsResolver resolver =
        new DefaultSSOProfileOptionsResolver(properties, defaultOptions);

    IamSSOProfileOptions options = resolver.resolveProfileOptions(ENTITY_ID_1);
    
    assertThat(options, is(customOpts));
    
  }


  @Test
  public void testMultiEntityCustomProfileResolution() {
    
    IamSSOProfileOptions customOpts = new IamSSOProfileOptions();
    customOpts.setSpidIdp(true);
    customOpts.setPassive(null);
    
    when(pp.getEntityIds()).thenReturn(Joiner.on(',').join(ENTITY_ID_1, ENTITY_ID_2));
    when(pp.getOptions()).thenReturn(customOpts);
    when(properties.getCustomProfile()).thenReturn(Lists.newArrayList(pp));
    
    DefaultSSOProfileOptionsResolver resolver =
        new DefaultSSOProfileOptionsResolver(properties, defaultOptions);

    assertThat(resolver.resolveProfileOptions(ENTITY_ID_1), is(customOpts));
    assertThat(resolver.resolveProfileOptions(ENTITY_ID_2), is(customOpts));
  }

}
