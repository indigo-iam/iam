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
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.authn.common.Conjunction;
import it.infn.mw.iam.authn.common.Disjunction;
import it.infn.mw.iam.authn.common.Error;
import it.infn.mw.iam.authn.common.Fail;
import it.infn.mw.iam.authn.common.Negation;
import it.infn.mw.iam.authn.common.Success;
import it.infn.mw.iam.authn.common.ValidatorResult;

@RunWith(MockitoJUnitRunner.class)
public class CompositeChecksTests {

  public static final Object CREDENTIAL = new Object();

  @Test
  public void negationTest() {

    Negation<Object> not = new Negation<>(asList(new Success<>()), null);

    assertThat(not.validate(CREDENTIAL).isFailure(), is(true));

    not = new Negation<>(asList(new Fail<>()), null);
    assertThat(not.validate(CREDENTIAL).isSuccess(), is(true));

    not = new Negation<>(asList(new Error<>()), null);
    assertThat(not.validate(CREDENTIAL).isError(), is(true));
  }


  @Test
  public void conjunctionTest() {

    Conjunction<Object> and = new Conjunction<>(asList(new Success<>(), new Success<>()), null);

    assertThat(and.validate(CREDENTIAL).isSuccess(), is(true));

    and = new Conjunction<Object>(asList(new Success<>(), new Fail<>()), null);

    assertThat(and.validate(CREDENTIAL).isFailure(), is(true));

    and = new Conjunction<Object>(asList(new Fail<>(), new Success<>()), null);

    assertThat(and.validate(CREDENTIAL).isFailure(), is(true));

    and = new Conjunction<Object>(asList(new Error<>(), new Success<>()), null);

    assertThat(and.validate(CREDENTIAL).isError(), is(true));
  }

  @Test
  public void disjunctionTest() {


    Disjunction<Object> or = new Disjunction<>(asList(new Success<>(), new Fail<>()), null);

    assertThat(or.validate(CREDENTIAL).isSuccess(), is(true));

    or = new Disjunction<>(asList(new Fail<>(), new Success<>()), null);

    assertThat(or.validate(CREDENTIAL).isSuccess(), is(true));

    or = new Disjunction<>(asList(new Fail<>(), new Fail<>()), null);

    assertThat(or.validate(CREDENTIAL).isFailure(), is(true));

    or = new Disjunction<>(asList(new Fail<>()), null);

    assertThat(or.validate(CREDENTIAL).isFailure(), is(true));

    or = new Disjunction<>(asList(new Fail<>(), new Error<>()), null);

    assertThat(or.validate(CREDENTIAL).isError(), is(true));
  }

  @Test
  public void failMessageTest() {
    Disjunction<Object> or = new Disjunction<>(asList(new Fail<>()), "yo");
    ValidatorResult result = or.validate(CREDENTIAL);
    assertThat(result.isFailure(), is(true));
    assertThat(result.getMessage(), is("yo"));

    Conjunction<Object> and = new Conjunction<>(asList(new Fail<>()), "yo");
    result = and.validate(CREDENTIAL);

    assertThat(result.isFailure(), is(true));
    assertThat(result.getMessage(), is("yo"));

    // Error message is not overridden
    or = new Disjunction<>(asList(new Error<>()), "yo");
    result = or.validate(CREDENTIAL);
    assertThat(result.isError(), is(true));
    assertThat(result.getMessage(), is("error"));

    and = new Conjunction<>(asList(new Error<>()), "yo");
    result = and.validate(CREDENTIAL);
    assertThat(result.isError(), is(true));
    assertThat(result.getMessage(), is("error"));

  }
}
