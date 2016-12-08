package it.infn.mw.iam.test.ext_authn.saml;

import java.util.Optional;

import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.opensaml.saml2.core.NameID;
import org.springframework.security.saml.SAMLCredential;

import it.infn.mw.iam.authn.saml.util.SamlAttributeNames;
import it.infn.mw.iam.authn.saml.util.SamlIdResolvers;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolver;

public class ResolverTests {


  @Test
  public void emptyNameIdResolverTest() {

    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    Mockito.when(cred.getNameID()).thenReturn(null);

    SamlUserIdentifierResolver resolver = SamlIdResolvers.nameid();

    Optional<String> resolvedId = resolver.getUserIdentifier(cred);

    Assert.assertFalse(resolvedId.isPresent());

  }

  @Test
  public void nameIdResolverTest() {
    NameID nameId = Mockito.mock(NameID.class);
    Mockito.when(nameId.getValue()).thenReturn("nameid");

    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    Mockito.when(cred.getNameID()).thenReturn(nameId);

    SamlUserIdentifierResolver resolver = SamlIdResolvers.nameid();

    Optional<String> resolvedId = resolver.getUserIdentifier(cred);

    Assert.assertThat(resolvedId.get(), Matchers.equalTo("nameid"));

  }

  @Test
  public void mailIdResolverTest() {
    SamlUserIdentifierResolver resolver = SamlIdResolvers.mail();
    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    Mockito.when(cred.getAttributeAsString(SamlAttributeNames.mail)).thenReturn("test@test.org");

    Optional<String> resolvedId = resolver.getUserIdentifier(cred);

    Assert.assertThat(resolvedId.get(), Matchers.equalTo("test@test.org"));
  }
}
