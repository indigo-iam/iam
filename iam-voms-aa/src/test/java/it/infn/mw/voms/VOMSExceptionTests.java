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
package it.infn.mw.voms;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import it.infn.mw.voms.aa.VOMSException;
import it.infn.mw.voms.aa.VOMSNamingException;

public class VOMSExceptionTests {
  
  @Test
  public void vomsExceptionWithMessageThrowableTest() {
    
    NullPointerException cause = new NullPointerException();
    VOMSException ex = new VOMSException("Testing the voms exception with message", cause);
    assertEquals("Testing the voms exception with message", ex.getMessage());
    assertEquals(cause, ex.getCause());
  }
  
  @Test
  public void vomsNamingExceptionWithMessageThrowableTest() {
    
    VOMSNamingException e = new VOMSNamingException("Message");
    assertEquals("Message", e.getMessage());
  }
}