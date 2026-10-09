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
package it.infn.mw.iam.util.crypto.benchmark;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import org.apache.commons.codec.binary.Base64;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

import it.infn.mw.iam.core.client.IamSha256PasswordEncoder;
import it.infn.mw.iam.util.crypto.IamHmacPasswordEncoder;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 10, time = 1)
@Fork(2)
@State(Scope.Benchmark)
public class PasswordEncoderBenchmark {

  @Param({"BCRYPT", "PBKDF2", "HMAC", "SHA256"})
  private String algorithm;

  private PasswordEncoder encoder;

  private String rawPassword;

  private String encodedPassword;

  private String generateSecret() {
    return Base64.encodeBase64URLSafeString(new BigInteger(512, new SecureRandom()).toByteArray())
      .substring(0, 72);
  }

  @Setup(Level.Trial)
  public void setup() {

    rawPassword = generateSecret();

    switch (algorithm) {

      case "BCRYPT":
        encoder = new BCryptPasswordEncoder();
        break;

      case "PBKDF2":
        encoder = new Pbkdf2PasswordEncoder();
        break;

      case "HMAC":
        encoder = new IamHmacPasswordEncoder("my-super-secret-master-key");
        break;

      case "SHA256":
        encoder = new IamSha256PasswordEncoder();
        break;

      default:
        throw new IllegalArgumentException(algorithm);
    }

    encodedPassword = encoder.encode(rawPassword);
  }

  @Benchmark
  public void match(Blackhole blackhole) {

    boolean matches = encoder.matches(rawPassword, encodedPassword);
    blackhole.consume(matches);
  }
}
