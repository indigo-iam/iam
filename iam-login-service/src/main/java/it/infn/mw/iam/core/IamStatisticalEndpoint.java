package it.infn.mw.iam.core;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@RestController
public class IamStatisticalEndpoint {

  @Autowired
  IamAccountRepository accountRepo;

  @GetMapping("/stats")
  public UserCount getStats() {
    long count = accountRepo.count();
    return new UserCount(String.valueOf(count));
  }
}
