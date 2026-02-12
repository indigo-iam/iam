package it.infn.mw.iam.api.registration.cern;

import java.util.Optional;

import org.springframework.context.annotation.Profile;
import org.springframework.web.client.RestClientException;

import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;

@Profile("cern")
public interface CernSecurityBlockingApiService {

  /**
   * Returns an @Optional object that contains the @VOPersonDTO related to the CERN username
   * provided as parameter or empty if not found.
   * 
   * @param userName
   * @return
   * @throws RestClientException in case of ApiErrors
   */
  Optional<VOPersonDTO> getSecurityBlockingRecord(String userName) throws RestClientException;

}