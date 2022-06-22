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
package it.infn.mw.iam.test.api.common;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import org.junit.Test;
import it.infn.mw.iam.api.common.OffsetPageable;

public class OffsetPageableTests {

  public OffsetPageableTests() {

  }

  @Test
  public void IllegalOffsetOnCreation() {

    try {
      new OffsetPageable(-1, 1);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("offset must be greater or equal to 0"));
    }
  }

  @Test
  public void IllegalCountOnCreation() {

    try {
      new OffsetPageable(1, 0);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("count must be a positive integer"));
    }
  }

  @Test
  public void checkPreviuosRounded() {

    OffsetPageable op = new OffsetPageable(5, 10);
    assertThat(op.hasPrevious(), is(true));
    assertThat(op.getPageNumber(), equalTo(0));
    op = (OffsetPageable) op.previousOrFirst();
    assertThat(op.getPageNumber(), equalTo(0));
  }

  @Test
  public void checkNavigation() {

    OffsetPageable op = new OffsetPageable(0, 10);
    assertThat(op.hasPrevious(), is(false));
    assertThat(op.getPageNumber(), equalTo(0));
    assertThat(op.previousOrFirst(), equalTo(op));
    op = (OffsetPageable) op.next();
    assertThat(op.hasPrevious(), is(true));
    assertThat(op.getPageNumber(), equalTo(1));
    op = (OffsetPageable) op.previousOrFirst();
    assertThat(op.getPageNumber(), equalTo(0));
    op = (OffsetPageable) op.next();
    op = (OffsetPageable) op.next();
    assertThat(op.getPageNumber(), equalTo(2));
    op = (OffsetPageable) op.first();
    assertThat(op.getPageNumber(), equalTo(0));
  }

  @Test
  public void checkToString() {

    OffsetPageable op = new OffsetPageable(0, 10);
    String expectedToString =
        String.format("OffsetPageable [offset=%d, count=%d]", op.getOffset(), op.getPageSize());
    assertThat(op.toString(), equalTo(expectedToString));
  }
}
