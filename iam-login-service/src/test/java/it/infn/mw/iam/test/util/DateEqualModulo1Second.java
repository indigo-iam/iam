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
package it.infn.mw.iam.test.util;

import java.util.Date;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

public class DateEqualModulo1Second extends TypeSafeMatcher<Date>  {

  private final Date expectedValue;
  
  public DateEqualModulo1Second(Date expectedValue) {
    this.expectedValue = expectedValue;
  }

  @Override
  public void describeTo(Description description) {
    description.appendValue(expectedValue);
    
  }

  @Override
  protected boolean matchesSafely(Date actualValue) {
    
    if (expectedValue == null) {
      return actualValue == null;
    }
    
    if (actualValue == null) {
      return false;
    }
    
    long actualTime = actualValue.getTime();
    long expectedTime = expectedValue.getTime();
    
    long diff = Math.abs(actualTime-expectedTime);
    
    return diff < 1000;
  }


}
