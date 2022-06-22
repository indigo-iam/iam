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
package it.infn.mw.voms.aa;

public enum VOMSWarning {

  OrderNotSatisfied(1, "The requested order could not be satisfied."),
  ShortenedAttributeValidity(
      2,
      "The validity period of the issued attributes has been shortened to the maximum allowed by "
      + "this VOMS server configuration."),
  AttributeSubset(3, "Only a subset of the requested attributes has been returned.");

  private int code;
  private String message;

  private VOMSWarning(int legacyCode, String message) {

    this.code = legacyCode;
    this.message = message;
  }

  public int getCode() {

    return code;
  }

  public String getDefaultMessage() {

    return message;
  }

}
