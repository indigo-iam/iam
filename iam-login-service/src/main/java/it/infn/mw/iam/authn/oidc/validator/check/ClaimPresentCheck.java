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
package it.infn.mw.iam.authn.oidc.validator.check;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Strings.isNullOrEmpty;
import static it.infn.mw.iam.authn.common.ValidatorResult.error;
import static it.infn.mw.iam.authn.common.ValidatorResult.failure;
import static it.infn.mw.iam.authn.common.ValidatorResult.success;
import static java.lang.String.format;
import static java.util.Objects.isNull;

import java.text.ParseException;

import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.authn.common.BaseValidatorCheck;
import it.infn.mw.iam.authn.common.ValidatorResult;

public class ClaimPresentCheck extends BaseValidatorCheck<JWT> {

  final String claimName;

  private ClaimPresentCheck(String claimName, String message) {
    super(message);
    this.claimName = claimName;
  }

  @Override
  public ValidatorResult validate(JWT jwt) {

    try {
      Object claimValue = jwt.getJWTClaimsSet().getClaim(claimName);

      if (isNull(claimValue)) {
        return handleFailure(failure(format("Claim '%s' not found", claimName)));
      }

      return success();

    } catch (ParseException e) {
      return error(format("JWT parse error: %s", e.getMessage()));
    }
  }

  public static ClaimPresentCheck hasClaim(String claimName) {
    return hasClaim(claimName, null);
  }

  public static ClaimPresentCheck hasClaim(String claimName, String message) {
    checkArgument(!isNullOrEmpty(claimName), "claimName must not be null or empty");
    return new ClaimPresentCheck(claimName, message);
  }

}
