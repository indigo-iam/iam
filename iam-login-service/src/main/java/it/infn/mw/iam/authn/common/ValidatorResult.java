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
package it.infn.mw.iam.authn.common;

import static it.infn.mw.iam.authn.common.ValidatorResult.Status.ERROR;
import static it.infn.mw.iam.authn.common.ValidatorResult.Status.FAILURE;
import static it.infn.mw.iam.authn.common.ValidatorResult.Status.SUCCESS;
import static java.util.Objects.nonNull;

public class ValidatorResult {

  public enum Status {
    SUCCESS,
    FAILURE,
    ERROR
  }

  private final Status status;
  private final String message;

  private ValidatorResult(Status s, String message) {
    this.status = s;
    this.message = message;
  }

  private ValidatorResult(Status s) {
    this(s, null);
  }

  public boolean hasMessage() {
    return nonNull(message);
  }

  public Status getStatus() {
    return status;
  }

  public String getMessage() {
    return message;
  }

  public boolean isSuccess() {
    return SUCCESS.equals(status);
  }
  
  public boolean isFailure() {
    return FAILURE.equals(status);
  }
  
  public boolean isError() {
    return ERROR.equals(status);
  }
  
  public static ValidatorResult success() {
    return new ValidatorResult(Status.SUCCESS);
  }

  public static ValidatorResult failure(String message) {
    return new ValidatorResult(Status.FAILURE, message);
  }

  public static ValidatorResult error(String message) {
    return new ValidatorResult(Status.ERROR, message);
  }

}
