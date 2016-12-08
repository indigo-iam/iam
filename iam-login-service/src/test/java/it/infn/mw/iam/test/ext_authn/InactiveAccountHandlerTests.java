package it.infn.mw.iam.test.ext_authn;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.DisabledException;

import it.infn.mw.iam.authn.DefaultInactiveAccountAuthenticationHandler;
import it.infn.mw.iam.core.IamProperties;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;


public class InactiveAccountHandlerTests {

  @Test
  public void inactiveAccountHandlerSilentlyIgnoresActiveAccount() {
    IamProperties.INSTANCE.setOrganisationName("test");

    IamAccount account = Mockito.mock(IamAccount.class);

    Mockito.when(account.isActive()).thenReturn(true);

    DefaultInactiveAccountAuthenticationHandler handler =
        new DefaultInactiveAccountAuthenticationHandler(IamProperties.INSTANCE);

    handler.handleInactiveAccount(account);

  }

  @Test
  public void inactiveAccountHandlerRaiseErrorForDisabledUser() {
    IamProperties.INSTANCE.setOrganisationName("test");

    IamAccount account = Mockito.mock(IamAccount.class);

    Mockito.when(account.isActive()).thenReturn(false);
    DefaultInactiveAccountAuthenticationHandler handler =
        new DefaultInactiveAccountAuthenticationHandler(IamProperties.INSTANCE);

    try {

      handler.handleInactiveAccount(account);
      fail("Expected exception not raised");

    } catch (DisabledException ex) {
      assertThat(ex.getMessage(), equalTo("Your account is suspended"));

    }
  }

  @Test
  public void inactiveAccountHandlerInformsOfRegistrationRequestWaitingConfirmation() {
    IamProperties.INSTANCE.setOrganisationName("test");
    IamRegistrationRequest req = Mockito.mock(IamRegistrationRequest.class);
    IamAccount account = Mockito.mock(IamAccount.class);

    Mockito.when(account.isActive()).thenReturn(false);
    Mockito.when(account.getRegistrationRequest()).thenReturn(req);
    Mockito.when(req.getStatus()).thenReturn(IamRegistrationRequestStatus.NEW);

    DefaultInactiveAccountAuthenticationHandler handler =
        new DefaultInactiveAccountAuthenticationHandler(IamProperties.INSTANCE);

    try {

      handler.handleInactiveAccount(account);


    } catch (DisabledException ex) {
      assertThat(ex.getMessage(), containsString("confirmation URL"));

    }
  }

  @Test
  public void inactiveAccountHandlerInformsOfRegistrationRequestWaitingForApproval() {
    IamProperties.INSTANCE.setOrganisationName("test");
    IamRegistrationRequest req = Mockito.mock(IamRegistrationRequest.class);
    IamAccount account = Mockito.mock(IamAccount.class);

    Mockito.when(account.isActive()).thenReturn(false);
    Mockito.when(account.getRegistrationRequest()).thenReturn(req);
    Mockito.when(req.getStatus()).thenReturn(IamRegistrationRequestStatus.CONFIRMED);

    DefaultInactiveAccountAuthenticationHandler handler =
        new DefaultInactiveAccountAuthenticationHandler(IamProperties.INSTANCE);

    try {

      handler.handleInactiveAccount(account);


    } catch (DisabledException ex) {
      assertThat(ex.getMessage(), containsString("administrator approval"));

    }
  }

  @Test
  public void inactiveAccountHandlerIgnoresApprovedRegistrationRequest() {
    IamProperties.INSTANCE.setOrganisationName("test");
    IamRegistrationRequest req = Mockito.mock(IamRegistrationRequest.class);
    IamAccount account = Mockito.mock(IamAccount.class);

    Mockito.when(account.isActive()).thenReturn(false);
    Mockito.when(account.getRegistrationRequest()).thenReturn(req);
    Mockito.when(req.getStatus()).thenReturn(IamRegistrationRequestStatus.APPROVED);

    DefaultInactiveAccountAuthenticationHandler handler =
        new DefaultInactiveAccountAuthenticationHandler(IamProperties.INSTANCE);

    try {

      handler.handleInactiveAccount(account);


    } catch (DisabledException ex) {
      assertThat(ex.getMessage(), equalTo("Your account is suspended"));

    }
  }
}
