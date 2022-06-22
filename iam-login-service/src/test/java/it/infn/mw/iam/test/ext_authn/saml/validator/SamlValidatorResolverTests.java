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
package it.infn.mw.iam.test.ext_authn.saml.validator;

import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.saml.SAMLCredential;

import it.infn.mw.iam.authn.common.Fail;
import it.infn.mw.iam.authn.common.Success;
import it.infn.mw.iam.authn.common.ValidatorResolver;
import it.infn.mw.iam.authn.common.config.DefaultValidatorConfigParser;
import it.infn.mw.iam.authn.common.config.ValidatorConfigParser;
import it.infn.mw.iam.authn.common.config.ValidatorProperties;
import it.infn.mw.iam.authn.saml.validator.DefaultSamlValidatorResolver;
import it.infn.mw.iam.config.saml.IamSamlProperties;
import it.infn.mw.iam.config.saml.IamSamlProperties.IssuerValidationProperties;

@RunWith(MockitoJUnitRunner.class)
public class SamlValidatorResolverTests {

  public static final String ENTITY_ID_1 = "e1";
  public static final String ENTITY_ID_2 = "e2";
  
  @Mock
  IamSamlProperties properties;

  ValidatorConfigParser configParser = new DefaultValidatorConfigParser();
  ValidatorResolver<SAMLCredential> resolver;
  
  @Test
  public void noValidatorsIsFine() {
    resolver = new DefaultSamlValidatorResolver(configParser, properties);
    assertThat(resolver.resolveChecks(ENTITY_ID_1).isPresent(), is(false));
  }
  
  @Test
  public void defaultValidatorUnderstood() {
    
    ValidatorProperties defaultProps = new ValidatorProperties();
    defaultProps.setKind("true");
    
    ValidatorProperties props = new ValidatorProperties();
    props.setKind("false");
    
    IssuerValidationProperties entityProps = new IssuerValidationProperties();
    entityProps.setEntityId(ENTITY_ID_1);
    entityProps.setValidator(props);
    
    when(properties.getDefaultValidator()).thenReturn(defaultProps);
    when(properties.getValidators()).thenReturn(asList(entityProps));
    
    resolver = new DefaultSamlValidatorResolver(configParser, properties);
    assertThat(resolver.resolveChecks(ENTITY_ID_1).isPresent(), is(true));
    assertThat(resolver.resolveChecks(ENTITY_ID_1).get(), instanceOf(Fail.class));
    assertThat(resolver.resolveChecks(ENTITY_ID_2).isPresent(), is(true));
    assertThat(resolver.resolveChecks(ENTITY_ID_2).get(), instanceOf(Success.class));
  }
}
