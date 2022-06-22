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
package it.infn.mw.iam.authn.common.config;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Strings.isNullOrEmpty;
import static it.infn.mw.iam.authn.saml.validator.check.SamlHasAttributeCheck.hasAttribute;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import it.infn.mw.iam.authn.common.Conjunction;
import it.infn.mw.iam.authn.common.Disjunction;
import it.infn.mw.iam.authn.common.Fail;
import it.infn.mw.iam.authn.common.Negation;
import it.infn.mw.iam.authn.common.Success;
import it.infn.mw.iam.authn.common.ValidatorCheck;
import it.infn.mw.iam.authn.oidc.validator.check.ClaimPresentCheck;
import it.infn.mw.iam.authn.oidc.validator.check.ClaimRegexpMatch;
import it.infn.mw.iam.authn.saml.validator.check.SamlAttributeValueRegexpMatch;

@Component
public class DefaultValidatorConfigParser implements ValidatorConfigParser {
  
  public static final String MESSAGE_PARAM = "message";
  public static final String ATTRIBUTE_NAME_PARAM = "attributeName";
  public static final String CLAIM_NAME_PARAM = "claimName";
  public static final String REGEXP_PARAM = "regexp";

  private static final Set<String> KIND = Set.of("or", "and", "not", "hasAttr",
      "attrValueMatches", "hasClaim", "claimValueMatches", "true", "false");

  @SuppressWarnings({"unchecked", "rawtypes"})
  protected ValidatorCheck<?> disjunction(ValidatorProperties p) {
    p.requireChildren();
    List<ValidatorCheck<?>> checks =
        p.getChildrens().stream().map(this::parseValidatorProperties).collect(Collectors.toList());
    return new Disjunction(checks, p.getOptionalParam(MESSAGE_PARAM));

  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  protected ValidatorCheck<?> conjunction(ValidatorProperties p) {
    p.requireChildren();
    List<ValidatorCheck<?>> checks =
        p.getChildrens().stream().map(this::parseValidatorProperties).collect(Collectors.toList());

    return new Conjunction(checks, p.getOptionalParam(MESSAGE_PARAM));
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  protected ValidatorCheck<?> negation(ValidatorProperties p) {
    p.requireChildren();
    List<ValidatorCheck<?>> checks =
        p.getChildrens().stream().map(this::parseValidatorProperties).collect(Collectors.toList());

    return new Negation(checks, p.getOptionalParam(MESSAGE_PARAM));
  }

  protected ValidatorCheck<?> hasAttr(ValidatorProperties p) {
    return hasAttribute(p.getRequiredNonEmptyParam(ATTRIBUTE_NAME_PARAM), p.getOptionalParam(MESSAGE_PARAM));
  }

  protected ValidatorCheck<?> hasClaim(ValidatorProperties p) {
    return ClaimPresentCheck.hasClaim(p.getRequiredNonEmptyParam(CLAIM_NAME_PARAM),
        p.getOptionalParam(MESSAGE_PARAM));
  }

  protected ValidatorCheck<?> claimValueMatches(ValidatorProperties p) {
    return ClaimRegexpMatch.claimMatches(p.getRequiredNonEmptyParam(CLAIM_NAME_PARAM),
        p.getRequiredNonEmptyParam(REGEXP_PARAM), p.getOptionalParam(MESSAGE_PARAM));
  }

  protected ValidatorCheck<?> attrValueMatches(ValidatorProperties p) {
    return SamlAttributeValueRegexpMatch.attrValueMatches(
        p.getRequiredNonEmptyParam(ATTRIBUTE_NAME_PARAM), p.getRequiredNonEmptyParam(REGEXP_PARAM),
        p.getOptionalParam(MESSAGE_PARAM));
  }

  @SuppressWarnings("unchecked")
  @Override
  public ValidatorCheck<?> parseValidatorProperties(ValidatorProperties p) {
    try {
      checkNotNull(p, "p must be non-null");
      checkArgument(!isNullOrEmpty(p.getKind()), "kind must be non-null and not empty");

      if (!KIND.contains(p.getKind())) {
        throw new ValidatorConfigError("Unsupported validator kind: " + p.getKind());
      }
      if ("or".equals(p.getKind())) {
        return disjunction(p);
      } else if ("and".equals(p.getKind())) {
        return conjunction(p);
      } else if ("not".equals(p.getKind())) {
        return negation(p);
      } else if ("hasAttr".equals(p.getKind())) {
        return hasAttr(p);
      } else if ("attrValueMatches".equals(p.getKind())) {
        return attrValueMatches(p);
      } else if ("hasClaim".equals(p.getKind())) {
        return hasClaim(p);
      } else if ("claimValueMatches".equals(p.getKind())) {
        return claimValueMatches(p);
      } else if ("true".equals(p.getKind())) {
        return new Success<>();
      } else if ("false".equals(p.getKind())) {
        return new Fail<>();
      }

      throw new IllegalArgumentException("Known but unsupported kind: " + p.getKind());

    } catch (IllegalArgumentException e) {
      throw new ValidatorConfigError(e);
    }
  }

}
