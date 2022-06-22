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
package it.infn.mw.iam.test.ext_authn.saml.jit_account_provisioning;


import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.in;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Optional;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import it.infn.mw.iam.config.saml.IamSamlJITAccountProvisioningProperties;

public class JitPropertiesTests {


  @Test
  public void testTrustedIdpsListIsByDefaultEmpty() {
    IamSamlJITAccountProvisioningProperties props = new IamSamlJITAccountProvisioningProperties();

    Assert.assertFalse(props.getTrustedIdpsAsOptionalSet().isPresent());
    
    props.setTrustedIdps("all");
    
    assertFalse(props.getTrustedIdpsAsOptionalSet().isPresent()); 
  }
  
  
  @Test
  public void testTrustedIdpsListParsing() {
    IamSamlJITAccountProvisioningProperties props = new IamSamlJITAccountProvisioningProperties();
    
    props.setTrustedIdps("idp1,idp2,idp3,,,    ");
    
    Optional<Set<String>> trustedIdps = props.getTrustedIdpsAsOptionalSet(); 
    
    assertTrue(trustedIdps.isPresent());
    
    assertThat(trustedIdps.get(), hasSize(3));
    assertThat("idp1", is(in(trustedIdps.get())));
    assertThat("idp2", is(in(trustedIdps.get())));
    assertThat("idp3", is(in(trustedIdps.get())));
  }
  
  
  @Test
  public void testTrustedIdpsEmptyListYeldsEmptyOptional() {
    IamSamlJITAccountProvisioningProperties props = new IamSamlJITAccountProvisioningProperties();
    
    props.setTrustedIdps("");
    Optional<Set<String>> trustedIdps = props.getTrustedIdpsAsOptionalSet(); 
    assertFalse(trustedIdps.isPresent());
    
  }

}
