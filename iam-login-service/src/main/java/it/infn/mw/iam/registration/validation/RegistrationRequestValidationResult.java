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

public class RegistrationRequestValidationResult {

  public enum Outcome {
    OK,
    INVALID,
    ERROR
  }

  private final Outcome outcome;
  private final String errorMessage;

  private RegistrationRequestValidationResult(Outcome outcome, String errorMessage) {
    this.outcome = outcome;
    this.errorMessage = errorMessage;
  }

  private RegistrationRequestValidationResult(Outcome outcome) {
    this(outcome, null);
  }

  public Outcome getOutcome() {
    return outcome;
  }

  public String getErrorMessage() {
    return errorMessage;
  }


  public boolean isOk() {
    return Outcome.OK.equals(outcome);
  }

  public static RegistrationRequestValidationResult ok() {
    return new RegistrationRequestValidationResult(Outcome.OK);
  }

  public static RegistrationRequestValidationResult invalid(String message) {
    return new RegistrationRequestValidationResult(Outcome.INVALID, message);
  }

  public static RegistrationRequestValidationResult error(String message) {
    return new RegistrationRequestValidationResult(Outcome.ERROR, message);
  }
}
