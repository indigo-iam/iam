package it.infn.mw.iam.api.common.validator;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class NoNewLineOrCarriageReturnValidator implements ConstraintValidator<NoNewLineOrCarriageReturn, String> {

  public NoNewLineOrCarriageReturnValidator() {
    // Empty on purpose
  }

  @Override
  public void initialize(NoNewLineOrCarriageReturn constraintAnnotation) {
    // Empty on purpose
  }

  @Override
  public boolean isValid(String value, ConstraintValidatorContext context) {
    return value == null || !value.matches(".*(?:[ \r\n\t].*)+");
  }

}
