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
package it.infn.mw.iam.test.scim.model;

import org.junit.Assert;
import org.junit.Test;

import it.infn.mw.iam.api.scim.model.ScimFilter;

public class ScimFilterTests {


    @Test
    public void scimFilterGetTest() {

        ScimFilter filter = new ScimFilter("anAttribute", "anOperator", "aValue");
        Assert.assertTrue(filter.getAttribute().equals("anAttribute"));
        Assert.assertTrue(filter.getOperator().equals("anOperator"));
        Assert.assertTrue(filter.getValue().equals("aValue"));
        Assert.assertTrue(filter.getClass().equals(ScimFilter.class));
    }

}
