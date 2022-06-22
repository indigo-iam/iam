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
package it.infn.mw.iam.test.api.aup;

import java.util.Date;

import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.test.api.TestSupport;

public class AupTestSupport extends TestSupport{
  
  public static final String DEFAULT_AUP_NAME = "default-aup";
  public static final String DEFAULT_AUP_URL = "http://default.aup.url/";
  public static final String DEFAULT_AUP_DESC = "default-aup-desc";


  public IamAup buildDefaultAup() {
    Date now = new Date();
    IamAup aup = new IamAup();
    
    aup.setName(DEFAULT_AUP_NAME);
    aup.setUrl(DEFAULT_AUP_URL);
    aup.setDescription(DEFAULT_AUP_DESC);
    aup.setCreationTime(now);
    aup.setLastUpdateTime(now);
    aup.setSignatureValidityInDays(365L);
    
    return aup;
  }

}
