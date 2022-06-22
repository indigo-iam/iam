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
package it.infn.mw.iam.test.oauth.exchange;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.core.oauth.exchange.ClientMatcherFactory;

@RunWith(MockitoJUnitRunner.class)
public class ClientMatcherFactoryTests extends TokenExchangePdpTestSupport{

  
  @Test(expected = IllegalArgumentException.class)
  public void nullClientIdNotAllowed() {
    
    try {
      ClientMatcherFactory.newClientMatcher(buildByIdClientMatcher(null));
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), containsString("<null> or empty clientId not allowed"));
      throw e;
    }
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void emptyClientIdNotAllowed() {
    
    try {
      ClientMatcherFactory.newClientMatcher(buildByIdClientMatcher(""));
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), containsString("<null> or empty clientId not allowed"));
      throw e;
    }
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void nullScopeNotAllowed() {
    
    try {
      ClientMatcherFactory.newClientMatcher(buildByScopeClientMatcher(null));
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), containsString("<null> or empty scope not allowed"));
      throw e;
    }
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void emptyScopeNotAllowed() {
    
    try {
      ClientMatcherFactory.newClientMatcher(buildByScopeClientMatcher(""));
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), containsString("<null> or empty scope not allowed"));
      throw e;
    }
  }

}
