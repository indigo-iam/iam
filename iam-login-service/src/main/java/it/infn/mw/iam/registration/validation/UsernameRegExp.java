package it.infn.mw.iam.registration.validation;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import javax.validation.Constraint;
import javax.validation.Payload;

@Retention(RUNTIME)
@Target({FIELD})
@Constraint(validatedBy = UsernameValidator.class)
public @interface UsernameRegExp {

  String message() default "invalid username (the provided username is not a valid UNIX username)";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};

}