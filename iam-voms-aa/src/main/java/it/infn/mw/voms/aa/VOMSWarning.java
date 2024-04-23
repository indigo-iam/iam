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

import static java.lang.String.format;

public class VOMSWarning {

  public static final String OrderNotSatisfiedMessage =
      "The requested order could not be satisfied.";
  public static final String ShortenedAttributeValidityMessage =
      "The validity of this VOMS AC in your proxy is shortened to %d seconds, "
          + "which is the maximum allowed by this VOMS server configuration.";
  public static final String AttributeSubsetMessage =
      "Only a subset of the requested attributes has been returned.";

  private int code;
  private String message;

  public static VOMSWarning orderNotSatisfied() {
    return new VOMSWarning(1, OrderNotSatisfiedMessage);
  }

  public static VOMSWarning shortenedAttributeValidity(long maxAcValidityInSeconds) {
    return new VOMSWarning(2, format(ShortenedAttributeValidityMessage, maxAcValidityInSeconds));
  }

  public static VOMSWarning attributeSubset() {
    return new VOMSWarning(3, AttributeSubsetMessage);
  }

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
