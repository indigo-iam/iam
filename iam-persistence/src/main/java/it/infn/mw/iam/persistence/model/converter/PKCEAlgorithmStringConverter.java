package it.infn.mw.iam.persistence.model.converter;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import it.infn.mw.iam.persistence.model.PKCEAlgorithm;

@Converter
public class PKCEAlgorithmStringConverter implements AttributeConverter<PKCEAlgorithm, String> {

    @Override
    public String convertToDatabaseColumn(PKCEAlgorithm attribute) {
        if (attribute != null) {
            return attribute.getName();
        } else {
            return null;
        }
    }

    /* (non-Javadoc)
     * @see javax.persistence.AttributeConverter#convertToEntityAttribute(java.lang.Object)
     */
    @Override
    public PKCEAlgorithm convertToEntityAttribute(String dbData) {
        if (dbData != null) {
            return PKCEAlgorithm.parse(dbData);
        } else {
            return null;
        }
    }

}
