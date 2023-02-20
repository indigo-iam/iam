package it.infn.mw.iam.registration.validation;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

@Component
@Scope("prototype")
public class UsernameValidator implements ConstraintValidator<UsernameRegExp, String>{

  //Regular expression from https://unix.stackexchange.com/a/435120
  public final static String DEFAULT_REG_EXP = "^[a-z_]([a-z0-9_.-]{0,31}|[a-z0-9_.-]{0,30}\\$)$";

  Pattern pattern;

  public UsernameValidator() {
    this.pattern = Pattern.compile(DEFAULT_REG_EXP);
  }

  @Override
  public boolean isValid(String value, ConstraintValidatorContext context) {
    Matcher matcher = pattern.matcher(value);
    return matcher.matches();
  }

}
