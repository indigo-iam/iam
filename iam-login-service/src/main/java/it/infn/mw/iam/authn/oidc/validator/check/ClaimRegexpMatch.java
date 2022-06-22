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
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.authn.common.BaseValidatorCheck;
import it.infn.mw.iam.authn.common.ValidatorResult;

public class ClaimRegexpMatch extends BaseValidatorCheck<JWT> {
  public static final Logger LOG = LoggerFactory.getLogger(ClaimRegexpMatch.class);

  private final String claimName;
  private final String regexp;
  private final Pattern pattern;

  private ClaimRegexpMatch(String claimName, String regexp, String message) {
    super(message);
    this.claimName = claimName;
    this.regexp = regexp;
    this.pattern = Pattern.compile(regexp);
  }

  protected ValidatorResult handleStringValue(String claimValue) {

    if (pattern.matcher(claimValue).matches()) {
      return success();
    } else {
      final String noMatchMessage =
          format("Claim '%s' value '%s' does not match regexp: '%s'", claimName, claimValue, regexp);
      return handleFailure(failure(noMatchMessage));
    }
  }

  protected ValidatorResult handleStringArrayValue(String[] claimValue) {
    for (String v : claimValue) {
      if (pattern.matcher(v).matches()) {
        return success();
      }
    }

    return handleFailure(failure(format("No claim '%s' value found matching regexp: '%s'", claimName, regexp)));
  }

  @Override
  public ValidatorResult validate(JWT idToken) {

    try {
      Object claimValue = idToken.getJWTClaimsSet().getClaim(claimName);

      if (isNull(claimValue)) {
        return handleFailure(failure(format("Claim '%s' not found", claimName)));
      }

      if (claimValue instanceof String) {
        return handleStringValue((String) claimValue);
      } else if (claimValue instanceof String[]) {
        return handleStringArrayValue((String[]) claimValue);
      } else {
        return handleFailure(failure(
            format("Claim '%s' cannot be extracted as a string or string array", claimName)));
      }
    } catch (ParseException e) {
      return error(format("JWT parse error: %s", e.getMessage()));
    }

  }

  public static ClaimRegexpMatch claimMatches(String claimName, String regexp) {
    return claimMatches(claimName, regexp, null);
  }
  public static ClaimRegexpMatch claimMatches(String claimName, String regexp, String message) {
    checkArgument(!isNullOrEmpty(claimName), "claimName must not be null or empty");
    checkArgument(!isNullOrEmpty(regexp), "regexp must not be null or empty");
    return new ClaimRegexpMatch(claimName, regexp, message);
  }
}
