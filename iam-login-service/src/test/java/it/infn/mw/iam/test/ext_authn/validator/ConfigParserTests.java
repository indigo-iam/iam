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
package it.infn.mw.iam.test.ext_authn.validator;

import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.saml.SAMLCredential;

import com.google.common.collect.ImmutableMap;

import it.infn.mw.iam.authn.common.Conjunction;
import it.infn.mw.iam.authn.common.Disjunction;
import it.infn.mw.iam.authn.common.Negation;
import it.infn.mw.iam.authn.common.ValidatorCheck;
import it.infn.mw.iam.authn.common.config.DefaultValidatorConfigParser;
import it.infn.mw.iam.authn.common.config.ValidatorConfigError;
import it.infn.mw.iam.authn.common.config.ValidatorConfigParser;
import it.infn.mw.iam.authn.common.config.ValidatorProperties;
import it.infn.mw.iam.authn.saml.validator.check.SamlHasAttributeCheck;

@ExtendWith(MockitoExtension.class)
class ConfigParserTests {

  @Spy
  ValidatorProperties properties = new ValidatorProperties();

  ValidatorConfigParser configParser = new DefaultValidatorConfigParser();

  @Test
  void kindIsRequired() {

    ValidatorConfigError e = assertThrows(ValidatorConfigError.class,
        () -> configParser.parseValidatorProperties(properties));
    assertThat(e.getMessage(), containsString("kind must be non-null"));
  }

  @Test
  void kindNonEmpty() {

    when(properties.getKind()).thenReturn("");
    ValidatorConfigError e = assertThrows(ValidatorConfigError.class,
        () -> configParser.parseValidatorProperties(properties));
    assertThat(e.getMessage(), containsString("kind must be non-null"));
  }

  @Test
  void kindMustBeKnown() {

    when(properties.getKind()).thenReturn("unknown");
    ValidatorConfigError e = assertThrows(ValidatorConfigError.class,
        () -> configParser.parseValidatorProperties(properties));
    assertThat(e.getMessage(), containsString("Unsupported validator kind"));
  }

  @Test
  void hasAttributeRequiresAttributeName() {

    properties.setKind("hasAttr");
    ValidatorConfigError e = assertThrows(ValidatorConfigError.class,
        () -> configParser.parseValidatorProperties(properties));
    assertThat(e.getMessage(), containsString("attributeName param required"));
  }

  @Test
  void hasAttributeRequiresNonEmptyAttributeName() {

    properties.setParams(ImmutableMap.of("attributeName", ""));
    properties.setKind("hasAttr");
    ValidatorConfigError e = assertThrows(ValidatorConfigError.class,
        () -> configParser.parseValidatorProperties(properties));
    assertThat(e.getMessage(), containsString("attributeName param required"));
  }

  @Test
  void hasAttribute() {

    properties.setParams(ImmutableMap.of("attributeName", "1.2.3.4"));
    properties.setKind("hasAttr");

    @SuppressWarnings("rawtypes")
    ValidatorCheck hasAttr = configParser.parseValidatorProperties(properties);
    assertThat(hasAttr, instanceOf(SamlHasAttributeCheck.class));
  }

  @Test
  void disjunctionRequiresChildren() {

    properties.setKind("or");
    ValidatorConfigError e = assertThrows(ValidatorConfigError.class,
        () -> configParser.parseValidatorProperties(properties));
    assertThat(e.getMessage(), containsString("children validators required"));
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  @Test
  void disjunctionRecognized() {

    ValidatorProperties child1 = new ValidatorProperties();
    child1.setKind("hasAttr");
    child1.setParams(ImmutableMap.of("attributeName", "1.2.3.4"));

    ValidatorProperties child2 = new ValidatorProperties();
    child2.setKind("hasAttr");
    child2.setParams(ImmutableMap.of("attributeName", "3.4.5.6"));

    properties.setChildrens(asList(child1, child2));
    properties.setKind("or");

    ValidatorCheck or = configParser.parseValidatorProperties(properties);
    assertThat(or, instanceOf(Disjunction.class));

    Disjunction<SAMLCredential> typedOr = (Disjunction<SAMLCredential>) or;
    assertThat(typedOr.getChecks(), hasSize(2));
    assertThat(typedOr.getChecks().get(0), instanceOf(SamlHasAttributeCheck.class));
    assertThat(typedOr.getChecks().get(1), instanceOf(SamlHasAttributeCheck.class));
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  @Test
  void nestedStructureRecognized() {

    ValidatorProperties child0 = new ValidatorProperties();
    child0.setKind("hasAttr");
    child0.setParams(ImmutableMap.of("attributeName", "1.2.3.4.5"));

    ValidatorProperties child2 = new ValidatorProperties();
    child2.setKind("hasAttr");
    child2.setParams(ImmutableMap.of("attributeName", "3.4.5.6"));

    ValidatorProperties child1 = new ValidatorProperties();
    child1.setKind("not");
    child1.setChildrens(asList(child2));

    properties.setChildrens(asList(child0, child1));
    properties.setKind("and");

    ValidatorCheck and = configParser.parseValidatorProperties(properties);
    assertThat(and, instanceOf(Conjunction.class));

    Conjunction<SAMLCredential> typedAnd = (Conjunction<SAMLCredential>) and;
    assertThat(typedAnd.getChecks(), hasSize(2));
    assertThat(typedAnd.getChecks().get(0), instanceOf(SamlHasAttributeCheck.class));
    assertThat(typedAnd.getChecks().get(1), instanceOf(Negation.class));

    Negation<SAMLCredential> not = (Negation<SAMLCredential>) typedAnd.getChecks().get(1);
    assertThat(not.getChecks(), hasSize(1));
    assertThat(not.getChecks().get(0), instanceOf(SamlHasAttributeCheck.class));
  }

}
