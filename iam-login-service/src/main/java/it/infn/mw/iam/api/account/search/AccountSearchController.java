package it.infn.mw.iam.api.account.search;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.google.common.collect.Lists;
import it.infn.mw.iam.api.account.search.model.IamAccountDTO;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.common.PagedResourceService;
import it.infn.mw.iam.persistence.model.IamAccount;

@RestController
@Transactional
@PreAuthorize("hasRole('ADMIN')")
@RequestMapping(AccountSearchController.ACCOUNT_SEARCH_ENDPOINT)
public class AccountSearchController {

  public static final String ACCOUNT_SEARCH_ENDPOINT = "/iam/account/search";
  public static final int ITEMS_PER_PAGE = 10;

  @Autowired
  private PagedResourceService<IamAccount> accountService;

  @RequestMapping(method = RequestMethod.GET)
  public ListResponseDTO<IamAccountDTO> getAccounts(
      @RequestParam(required = false, defaultValue = "") String filter,
      @RequestParam(required = false, defaultValue = "1") int startIndex,
      @RequestParam(required = false, defaultValue = "10") int count) {

    ListResponseDTO.Builder<IamAccountDTO> response = new ListResponseDTO.Builder<>();

    if (count == 0) {

      /* returns total amount of users - no resources */
      long totalResults = 0;

      if (filter.isEmpty()) {

        totalResults = accountService.count();

      } else {

        totalResults = accountService.count(filter);
      }

      response.totalResults(totalResults);

    } else {

      OffsetPageable op = new OffsetPageable(startIndex - 1, count);

      Page<IamAccount> accounts;

      if (filter.isEmpty()) {

        accounts = accountService.getPage(op);

      } else {

        accounts = accountService.getPage(op, filter);
      }

      List<IamAccountDTO> resources = Lists.newArrayList();
      accounts.getContent().forEach(account -> resources.add(IamAccountDTO.builder().fromIamAccount(account).build()));
      response.resources(resources);
      response.itemsPerPage(accounts.getNumberOfElements());
      response.startIndex(startIndex);
      response.totalResults(accounts.getTotalElements());

    }

    return response.build();
  }

}