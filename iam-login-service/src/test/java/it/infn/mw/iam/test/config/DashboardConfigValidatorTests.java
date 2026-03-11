package it.infn.mw.iam.test.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import javax.validation.ConstraintValidatorContext;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import it.infn.mw.iam.api.client.management.validation.DashboardConfigValidator;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;

public class DashboardConfigValidatorTests {

  private final DashboardConfigValidator validator = new DashboardConfigValidator();
  private final ConstraintValidatorContext context = mock(ConstraintValidatorContext.class);
  private static DashboardProperties dashboardProperties;

  @BeforeEach
  void setup() {
    dashboardProperties = new DashboardProperties();
    dashboardProperties.setEnabled(true);
    dashboardProperties.setClientId("123e4567-e89b-12d3-a456-426655440000");
    dashboardProperties.setClientSecret("0tlkqGPJD2vWN1dgTqi3xn-PAJ7EMgNKFFUOydZPsTLkIouqQFmfioJcvfk0V2Xt");
  }

  @Test
  void testSkipValidation() {
    dashboardProperties = new DashboardProperties();
    dashboardProperties.setEnabled(false);
    dashboardProperties.setClientId(null);
    dashboardProperties.setClientSecret(null);
    boolean isValid = validator.isValid(dashboardProperties, context);

    assertTrue(isValid);
  }

  @Test
  void testDashboardPropertiesValid() {
    boolean isValid = validator.isValid(dashboardProperties, context);

    assertTrue(isValid);
  }

  @Test
  void testIsNotValidDashboardSecret() {
    dashboardProperties.setClientSecret("too-short-client-secret");
    boolean isValid = validator.isValid(dashboardProperties, context);

    assertFalse(isValid);
  }

  @Test
  void testIsNotValidDashboardSecretTooLong() {
    dashboardProperties.setClientSecret("too-long-client-secret-82gbV6OEwGBCPMmcFPXg5-4wRJXnKc-4wds5odwrFiY4wds5odwrF");
    boolean isValid = validator.isValid(dashboardProperties, context);

    assertFalse(isValid);
  }

  @Test
  void testIsNotValidDashboardSecretInvalidChars() {
    dashboardProperties.setClientSecret("0tlkqGPJD2vWN1/dgTqi3xn-PAJ7EMgNKFFUOydZPsTLkIouqQFmfioJcvfk0V2Xt");
    boolean isValid = validator.isValid(dashboardProperties, context);

    assertFalse(isValid);
  }

  @Test
  void testIsNotValidDashboardSecretInvalidNull() {
    dashboardProperties.setClientSecret(null);
    boolean isValid = validator.isValid(dashboardProperties, context);

    assertFalse(isValid);
  }

  @Test
  void testIsNotValidDashboardClientIdInvalidUUID() {
    dashboardProperties.setClientId("3xn-PAJ7EMgNKFFUOydZPsTLkIouqQFmfioJcvfk0V2Xt");
    boolean isValid = validator.isValid(dashboardProperties, context);

    assertFalse(isValid);
  }

  @Test
  void testIsNotValidDashboardClientIdNull() {
    dashboardProperties.setClientId(null);
    boolean isValid = validator.isValid(dashboardProperties, context);

    assertFalse(isValid);
  }
}
