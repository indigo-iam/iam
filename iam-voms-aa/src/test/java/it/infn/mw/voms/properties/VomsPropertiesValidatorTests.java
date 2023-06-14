package it.infn.mw.voms.properties;

import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import it.infn.mw.voms.properties.VomsProperties.VOMSAAProperties;

public class VomsPropertiesValidatorTests {
  private static ValidatorFactory validatorFactory;
  private static Validator validator;

  @BeforeClass
  public static void createValidator() {
    validatorFactory = Validation.buildDefaultValidatorFactory();
    validator = validatorFactory.getValidator();
  }

  @AfterClass
  public static void close() {
    validatorFactory.close();
  }

  @Test
  public void invalidUppercaseVoName() {
    VOMSAAProperties vomsaa = new VOMSAAProperties();
    vomsaa.setHost("vo-host");
    vomsaa.setVoName("VO-name");
    Set<ConstraintViolation<VOMSAAProperties>> violations = validator.validate(vomsaa);
    assertFalse(violations.isEmpty());
  }

  @Test
  public void validDowncaseVoName() {
    VOMSAAProperties vomsaa = new VOMSAAProperties();
    vomsaa.setVoName("vo-name");
    vomsaa.setHost("vo-host");
    Set<ConstraintViolation<VOMSAAProperties>> violations = validator.validate(vomsaa);
    assertTrue(violations.isEmpty());
  } 
}
