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
package it.infn.mw.iam.test.ext_authn.oidc.validator;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;

import org.junit.Test;
import org.mockito.Mockito;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import it.infn.mw.iam.authn.common.ValidatorCheck;
import it.infn.mw.iam.authn.common.ValidatorResult;
import it.infn.mw.iam.authn.oidc.validator.check.ClaimRegexpMatch;

public class ClaimRegexpMatchTests extends JWTTestSupport {

  @Test
  public void claimNotFound() {

    JWT jwt = new PlainJWT(claimSetBuilder().build());

    ValidatorCheck<JWT> check = ClaimRegexpMatch.claimMatches("entitlement", "admin|user");

    ValidatorResult result = check.validate(jwt);
    assertThat(result.isFailure(), is(true));
    assertThat(result.getMessage(), containsString("Claim 'entitlement' not found"));
  }

  @Test
  public void stringClaimMatches() {
    JWTClaimsSet.Builder builder = claimSetBuilder();
    builder.claim("entitlement", "sheriff");

    JWT jwt = new PlainJWT(builder.build());

    ValidatorCheck<JWT> check =
        ClaimRegexpMatch.claimMatches("entitlement", "sheriff|major");
    ValidatorResult result = check.validate(jwt);
    assertThat(result.isSuccess(), is(true));
  }

  @Test
  public void stringClaimDoesNotMatch() {
    JWTClaimsSet.Builder builder = claimSetBuilder();
    builder.claim("entitlement", "sheriff");

    JWT jwt = new PlainJWT(builder.build());

    ValidatorCheck<JWT> check =
        ClaimRegexpMatch.claimMatches("entitlement", "general|president");
    ValidatorResult result = check.validate(jwt);
    assertThat(result.isFailure(), is(true));
    assertThat(result.getMessage(),
        containsString("Claim 'entitlement' value 'sheriff' does not match regexp: 'general|president'"));
  }

  @Test
  public void emptyClaimMatchTest() {

    JWTClaimsSet.Builder builder = claimSetBuilder();
    builder.claim("empty_claim", "");

    JWT jwt = new PlainJWT(builder.build());
    ValidatorCheck<JWT> check = ClaimRegexpMatch.claimMatches("empty_claim", ".*");
    ValidatorResult result = check.validate(jwt);
    assertThat(result.isSuccess(), is(true));


  }

  @Test
  public void stringArrayClaimMatchTest() {

    JWTClaimsSet.Builder builder = claimSetBuilder();

    String[] values = {"one", "two", "three"};
    builder.claim("array_claim", values);

    JWT jwt = new PlainJWT(builder.build());
    ValidatorCheck<JWT> check = ClaimRegexpMatch.claimMatches("array_claim", "one|five");
    ValidatorResult result = check.validate(jwt);
    assertThat(result.isSuccess(), is(true));
  }

  @Test
  public void stringArrayNoFailureMatchTest() {

    JWTClaimsSet.Builder builder = claimSetBuilder();

    String[] values = {"one", "two", "three"};
    builder.claim("array_claim", values);

    JWT jwt = new PlainJWT(builder.build());
    ValidatorCheck<JWT> check = ClaimRegexpMatch.claimMatches("array_claim", "ciccio");
    ValidatorResult result = check.validate(jwt);
    assertThat(result.isFailure(), is(true));
    assertThat(result.getMessage(),
        containsString("No claim 'array_claim' value found matching regexp: 'ciccio'"));

  }
  
  @Test(expected = IllegalArgumentException.class)
  public void nullRegexpContructionFails() {
    ClaimRegexpMatch.claimMatches("array_claim", null);
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void nullClaimContructionFails() {
    ClaimRegexpMatch.claimMatches(null, ".*");
  }
  
  @Test
  public void noStringValueTest() {
    JWTClaimsSet.Builder builder = claimSetBuilder();
    builder.expirationTime(Date.from(Instant.now()));
    JWT jwt = new PlainJWT(builder.build());
    ValidatorCheck<JWT> check = ClaimRegexpMatch.claimMatches("exp", "ciccio");
    ValidatorResult result = check.validate(jwt);
    assertThat(result.isFailure(), is(true));
  }
  
  @Test
  public void jwtParseExceptionHandled() throws Exception {
    JWT jwt = Mockito.mock(JWT.class);
    
    when(jwt.getJWTClaimsSet()).thenThrow(new ParseException("parse error",0));
    ValidatorCheck<JWT> check = ClaimRegexpMatch.claimMatches("test", ".*");
    ValidatorResult result = check.validate(jwt);
    assertThat(result.isError(), is(true));
    assertThat(result.getMessage(), is("JWT parse error: parse error"));
    
  }
}
