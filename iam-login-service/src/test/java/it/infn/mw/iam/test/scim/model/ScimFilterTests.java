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
import it.infn.mw.iam.api.scim.provisioning.model.ScimFilterAttributes;
import it.infn.mw.iam.api.scim.provisioning.model.ScimFilterOperators;

public class ScimFilterTests {


    @Test
    public void scimFilterGetTest() {

        ScimFilterAttributes attribute = ScimFilterAttributes.ACTIVE;
        ScimFilterOperators operator = ScimFilterOperators.EQUALS;
        String value  = "true";

        ScimFilter filter = new ScimFilter(attribute, operator, value);
        Assert.assertEquals(true, filter.getAttribute().equals(attribute));
        Assert.assertEquals(true, filter.getOperator().equals(operator));
        Assert.assertEquals(true, filter.getValue().equals(value));
        Assert.assertEquals(true, filter.getClass().equals(ScimFilter.class));
    }

}
