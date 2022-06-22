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
package it.infn.mw.iam.test.api.account.search.service;

import static it.infn.mw.iam.api.account.search.GroupSearchController.getSortByName;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.common.PagedResourceService;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class DefaultPagedGroupsServiceTests extends GroupServiceUtils {

  public final int ITEMS_PER_PAGE = 10;
  public final long TOTAL_TEST_GROUPS = 22L;
  private final int LAST_PAGE_NUMBER = (int) Math.ceil(TOTAL_TEST_GROUPS / ITEMS_PER_PAGE);
  private final int LAST_PAGE_SIZE = (int) (long) TOTAL_TEST_GROUPS % ITEMS_PER_PAGE;
  private final int LAST_PAGE_OFFSET = (int) (long) Math.floorDiv(TOTAL_TEST_GROUPS, ITEMS_PER_PAGE) * ITEMS_PER_PAGE;

  @Autowired
  private PagedResourceService<IamGroup> groupService;

  private Page<IamGroup> getPage(Pageable p) {

    Page<IamGroup> page = groupService.getPage(p);
    assertThat(page.getTotalElements(), equalTo(TOTAL_TEST_GROUPS));
    assertThat(page.getNumber(), equalTo(p.getPageNumber()));
    int expectedSize = isLast(p) ? LAST_PAGE_SIZE : ITEMS_PER_PAGE;
    assertThat(page.getNumberOfElements(), equalTo(expectedSize));
    assertThat(page.getContent(), hasSize(expectedSize));
    return page;
  }

  private boolean isLast(Pageable p) {
    return p.getPageNumber() == LAST_PAGE_NUMBER;
  }

  @Test
  public void getAllPagesSortedByNameAsc() {

    Pageable op = new OffsetPageable(ITEMS_PER_PAGE, getSortByName(Sort.Direction.ASC));
    Pageable current = op.first();

    while (current.getOffset() <= TOTAL_TEST_GROUPS) {
      Page<IamGroup> page = getPage(current);
      assertSortIsByNameAsc(page.getContent());
      current = current.next();
    }
  }

  @Test
  public void getAllPagesSortedByNameDesc() {

    Pageable op = new OffsetPageable(ITEMS_PER_PAGE, getSortByName(Sort.Direction.DESC));
    Pageable current = op.first();

    while (current.getOffset() <= TOTAL_TEST_GROUPS) {
      Page<IamGroup> page = getPage(current);
      assertSortIsByNameDesc(page.getContent());
      current = current.next();
    }
  }

  @Test
  public void testGetFirstPageSortByNameAsc() {

    OffsetPageable op = new OffsetPageable(0, ITEMS_PER_PAGE, getSortByName(Sort.Direction.ASC));
    Page<IamGroup> page = groupService.getPage(op);
    assertSortIsByNameAsc(page.getContent());
  }

  @Test
  public void testGetFirstPageSortByNameDesc() {

    OffsetPageable op = new OffsetPageable(0, ITEMS_PER_PAGE, getSortByName(Sort.Direction.DESC));
    Page<IamGroup> page = groupService.getPage(op);
    assertSortIsByNameDesc(page.getContent());
  }

  @Test
  public void testGetLastPageSortByNameAsc() {

    OffsetPageable op = new OffsetPageable(LAST_PAGE_OFFSET, ITEMS_PER_PAGE, getSortByName(Sort.Direction.ASC));
    Page<IamGroup> page = groupService.getPage(op);
    assertSortIsByNameAsc(page.getContent());
  }


  @Test
  public void testGetLastPageSortByNameDesc() {

    OffsetPageable op = new OffsetPageable(LAST_PAGE_OFFSET, ITEMS_PER_PAGE, getSortByName(Sort.Direction.DESC));
    Page<IamGroup> page = groupService.getPage(op);
    assertSortIsByNameDesc(page.getContent());
  }

  @Test
  public void testFilter() {

    OffsetPageable op = new OffsetPageable(0, ITEMS_PER_PAGE, getSortByName(Sort.Direction.ASC));
    Page<IamGroup> page = groupService.getPage(op, "Production");
    assertThat(page.getTotalElements(), equalTo(1L));
    assertThat(page.getNumber(), equalTo(0));
    assertThat(page.getNumberOfElements(), equalTo(1));
    assertThat(page.getContent(), hasSize(1));
    assertThat(page.getContent().get(0).getName(), equalTo("Production"));
  }

  @Test
  public void testFilterCount() {

    long totalResults = groupService.count("Production");
    assertThat(totalResults, equalTo(1L));
  }
}
