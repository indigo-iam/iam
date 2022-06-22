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

import static it.infn.mw.iam.authn.oidc.validator.check.ClaimPresentCheck.hasClaim;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

import java.text.ParseException;

import org.junit.Test;
import org.mockito.Mockito;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;

public class ClaimPresentCheckTests extends JWTTestSupport{

  @Test
  public void hasClaimWorkAsExpected() {

    JWT jwt = new PlainJWT(claimSetBuilder().build());
    assertThat(hasClaim("sub").validate(jwt).isSuccess(), is(true));
    assertThat(hasClaim("exp").validate(jwt).isFailure(), is(true));
  }
  
  
  @Test
  public void claimParseErrorHandled() throws ParseException {
    JWT jwt = Mockito.mock(JWT.class);
    
    when(jwt.getJWTClaimsSet()).thenThrow(new ParseException("parse error",0));
    assertThat(hasClaim("sub").validate(jwt).isError(), is(true));
    
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void nullClaimNotAllowed() {
    hasClaim(null);
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void emptyClaimNotAllowed() {
    hasClaim("");
  }

}
