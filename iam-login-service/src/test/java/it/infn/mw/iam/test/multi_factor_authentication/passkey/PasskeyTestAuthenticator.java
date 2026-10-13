/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.test.multi_factor_authentication.passkey;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.UUID;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

/**
 * A software WebAuthn authenticator that produces "none" attestations and assertions, so that the
 * server side of the ceremonies can be exercised without a browser
 */
public class PasskeyTestAuthenticator {

  public enum Algorithm {
    ES256, RS256
  }

  private static final byte FLAG_UP = 0x01;
  private static final byte FLAG_UV = 0x04;
  private static final byte FLAG_AT = 0x40;

  private final Algorithm algorithm;
  private final KeyPair keyPair;
  private final byte[] credentialId;
  private final UUID aaguid;
  private long signCount;

  public PasskeyTestAuthenticator(Algorithm algorithm) {
    this(algorithm, randomBytes(64), UUID.randomUUID());
  }

  public PasskeyTestAuthenticator(Algorithm algorithm, byte[] credentialId, UUID aaguid) {
    this.algorithm = algorithm;
    this.credentialId = credentialId;
    this.aaguid = aaguid;
    this.signCount = 0;
    try {
      if (Algorithm.ES256 == algorithm) {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        keyPair = generator.generateKeyPair();
      } else {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
      }
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static byte[] randomBytes(int size) {
    byte[] result = new byte[size];
    new SecureRandom().nextBytes(result);
    return result;
  }

  public static String base64Url(byte[] value) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
  }

  public static byte[] sha256(byte[] value) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(value);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static byte[] clientDataJSON(String type, String challenge, String origin) {
    String json = "{\"type\":\"" + type + "\",\"challenge\":\"" + challenge + "\",\"origin\":\""
        + origin + "\",\"crossOrigin\":false}";
    return json.getBytes(StandardCharsets.UTF_8);
  }

  public byte[] getCredentialId() {
    return credentialId.clone();
  }

  public String getCredentialIdBase64Url() {
    return base64Url(credentialId);
  }

  public UUID getAaguid() {
    return aaguid;
  }

  public long getSignCount() {
    return signCount;
  }

  public void setSignCount(long signCount) {
    this.signCount = signCount;
  }

  /**
   * Builds the attestationObject of a "none" attestation for the given Relying Party
   */
  public byte[] attestationObject(String rpId, boolean userVerified) {
    byte flags = (byte) (FLAG_UP | FLAG_AT | (userVerified ? FLAG_UV : 0));
    try {
      byte[] authData = authenticatorData(rpId, flags, true);
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      CBORGenerator gen = new CBORFactory().createGenerator(bos);
      gen.writeStartObject(3);
      gen.writeFieldName("fmt");
      gen.writeString("none");
      gen.writeFieldName("attStmt");
      gen.writeStartObject(0);
      gen.writeEndObject();
      gen.writeFieldName("authData");
      gen.writeBinary(authData);
      gen.writeEndObject();
      gen.close();
      return bos.toByteArray();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  public static class Assertion {

    private final byte[] authenticatorData;
    private final byte[] signature;

    Assertion(byte[] authenticatorData, byte[] signature) {
      this.authenticatorData = authenticatorData;
      this.signature = signature;
    }

    public byte[] getAuthenticatorData() {
      return authenticatorData;
    }

    public byte[] getSignature() {
      return signature;
    }
  }

  /**
   * Signs an assertion for the given Relying Party and client data, advancing the signature
   * counter to the given value
   */
  public Assertion sign(String rpId, byte[] clientDataJSON, boolean userVerified,
      long newSignCount) {
    this.signCount = newSignCount;
    byte flags = (byte) (FLAG_UP | (userVerified ? FLAG_UV : 0));
    try {
      byte[] authData = authenticatorData(rpId, flags, false);
      byte[] toSign = ByteBuffer.allocate(authData.length + 32)
        .put(authData)
        .put(sha256(clientDataJSON))
        .array();
      Signature signature = Signature
        .getInstance(Algorithm.ES256 == algorithm ? "SHA256withECDSA" : "SHA256withRSA");
      signature.initSign(keyPair.getPrivate());
      signature.update(toSign);
      return new Assertion(authData, signature.sign());
    } catch (IOException | GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private byte[] authenticatorData(String rpId, byte flags, boolean withCredential)
      throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
    out.write(flags);
    out.write(ByteBuffer.allocate(4).putInt((int) signCount).array());
    if (withCredential) {
      ByteBuffer id = ByteBuffer.allocate(16);
      id.putLong(aaguid.getMostSignificantBits());
      id.putLong(aaguid.getLeastSignificantBits());
      out.write(id.array());
      out.write(ByteBuffer.allocate(2).putShort((short) credentialId.length).array());
      out.write(credentialId);
      out.write(coseKey());
    }
    return out.toByteArray();
  }

  private byte[] coseKey() throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    CBORGenerator gen = new CBORFactory().createGenerator(bos);
    if (Algorithm.ES256 == algorithm) {
      ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
      gen.writeStartObject(5);
      gen.writeFieldId(1);
      gen.writeNumber(2);
      gen.writeFieldId(3);
      gen.writeNumber(-7);
      gen.writeFieldId(-1);
      gen.writeNumber(1);
      gen.writeFieldId(-2);
      gen.writeBinary(fixedLength(pub.getW().getAffineX(), 32));
      gen.writeFieldId(-3);
      gen.writeBinary(fixedLength(pub.getW().getAffineY(), 32));
      gen.writeEndObject();
    } else {
      RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
      gen.writeStartObject(4);
      gen.writeFieldId(1);
      gen.writeNumber(3);
      gen.writeFieldId(3);
      gen.writeNumber(-257);
      gen.writeFieldId(-1);
      gen.writeBinary(unsigned(pub.getModulus()));
      gen.writeFieldId(-2);
      gen.writeBinary(unsigned(pub.getPublicExponent()));
      gen.writeEndObject();
    }
    gen.close();
    return bos.toByteArray();
  }

  private static byte[] unsigned(BigInteger value) {
    byte[] bytes = value.toByteArray();
    if (bytes[0] == 0) {
      byte[] result = new byte[bytes.length - 1];
      System.arraycopy(bytes, 1, result, 0, result.length);
      return result;
    }
    return bytes;
  }

  private static byte[] fixedLength(BigInteger value, int length) {
    byte[] bytes = unsigned(value);
    byte[] result = new byte[length];
    System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
    return result;
  }
}
