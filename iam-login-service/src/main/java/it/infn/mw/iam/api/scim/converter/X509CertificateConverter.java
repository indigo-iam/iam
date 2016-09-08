package it.infn.mw.iam.api.scim.converter;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.exception.ScimValidationException;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.util.x509.X509Utils;

@Service
public class X509CertificateConverter
    implements Converter<ScimX509Certificate, IamX509Certificate> {

  /**
   * <ul>
   * <li>scim.value => certificate</li>
   * <li>scim.display => label</li>
   * <li>scim.primary => primary</li>
   * <li>scim.certificateSubject => must be extract from certificate</li>
   * </ul>
   */

  @Override
  public IamX509Certificate fromScim(ScimX509Certificate scim) throws ScimValidationException {

    IamX509Certificate cert = new IamX509Certificate();

    cert.setCertificate(scim.getValue());
    cert.setLabel(scim.getDisplay());

    if (scim.isPrimary() != null) {
      cert.setPrimary(scim.isPrimary());
    } else {
      cert.setPrimary(false);
    }
    
    cert.setCertificateSubject(X509Utils.getCertificateSubject(scim.getValue()));

    return cert;
  }

  @Override
  public ScimX509Certificate toScim(IamX509Certificate entity) {

    return ScimX509Certificate.builder()
      .primary(entity.isPrimary())
      .display(entity.getLabel())
      .value(entity.getCertificate())
      .build();
  }
}
