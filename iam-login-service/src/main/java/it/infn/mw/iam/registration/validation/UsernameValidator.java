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
