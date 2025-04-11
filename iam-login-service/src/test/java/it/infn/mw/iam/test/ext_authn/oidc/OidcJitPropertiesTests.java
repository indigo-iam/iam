package it.infn.mw.iam.test.ext_authn.oidc;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.in;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Optional;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import it.infn.mw.iam.config.oidc.IamOidcJITAccountProvisioningProperties;

public class OidcJitPropertiesTests {

  @Test
  public void testTrustedIdpsListIsByDefaultEmpty() {
    IamOidcJITAccountProvisioningProperties props = new IamOidcJITAccountProvisioningProperties();

    Assert.assertFalse(props.getTrustedIdpsAsOptionalSet().isPresent());
    assertEquals("all", props.getTrustedIdps());

    props.setTrustedIdps("all");

    assertFalse(props.getTrustedIdpsAsOptionalSet().isPresent());
  }

  @Test
  public void testTrustedIdpsListParsing() {
    IamOidcJITAccountProvisioningProperties props = new IamOidcJITAccountProvisioningProperties();

    props.setTrustedIdps("idp1,idp2,idp3,,,    ");

    Optional<Set<String>> trustedIdps = props.getTrustedIdpsAsOptionalSet();

    assertTrue(trustedIdps.isPresent());

    assertThat(trustedIdps.get(), hasSize(3));
    assertThat("idp1", is(in(trustedIdps.get())));
    assertThat("idp2", is(in(trustedIdps.get())));
    assertThat("idp3", is(in(trustedIdps.get())));
  }

  @Test
  public void testTrustedIdpsEmptyListYeldsEmptyOptional() {
    IamOidcJITAccountProvisioningProperties props = new IamOidcJITAccountProvisioningProperties();

    props.setTrustedIdps("");
    Optional<Set<String>> trustedIdps = props.getTrustedIdpsAsOptionalSet();
    assertFalse(trustedIdps.isPresent());
  }

  @Test
  public void testCleanupTaskEnabledDefaultAndSetter() {
    IamOidcJITAccountProvisioningProperties props = new IamOidcJITAccountProvisioningProperties();

    assertFalse(props.getCleanupTaskEnabled());

    props.setCleanupTaskEnabled(true);
    assertTrue(props.getCleanupTaskEnabled());
  }

  @Test
  public void testCleanupTaskPeriodSetterGetter() {
    IamOidcJITAccountProvisioningProperties props = new IamOidcJITAccountProvisioningProperties();

    assertEquals(86400L, props.getCleanupTaskPeriodSec());

    props.setCleanupTaskPeriodSec(3600L);
    assertEquals(3600L, props.getCleanupTaskPeriodSec());
  }

  @Test
  public void testInactiveAccountLifetimeDaysSetterGetter() {
    IamOidcJITAccountProvisioningProperties props = new IamOidcJITAccountProvisioningProperties();

    assertEquals(15, props.getInactiveAccountLifetimeDays());

    props.setInactiveAccountLifetimeDays(30);
    assertEquals(Integer.valueOf(30), props.getInactiveAccountLifetimeDays());
  }
}
