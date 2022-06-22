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

import com.nimbusds.jwt.JWTClaimsSet;

public class JWTTestSupport {
  
  public static final String JWT_SUB = "sub";
  public static final String JWT_ISS = "iss";
  public static final String JWT_ID = "1";
  
  
  protected JWTClaimsSet.Builder claimSetBuilder(){
    JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
    builder.jwtID(JWT_ID).subject(JWT_SUB).issuer(JWT_ISS);
    return builder;
  }

}
