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
package it.infn.mw.iam.test;

import java.util.ArrayList;
import java.util.List;

public class SshKeyUtils {

  public static final List<SshKey> sshKeys = new ArrayList<SshKey>();

  static {

    SshKey sshKey = new SshKey();
    sshKey.fingerprintSHA256 = "iXUu+MjanRMxt+Sd9qkw7J2y7xYP/FRodd4lxHnc7zA=";
    sshKey.fingerprintMD5Formatted = "d6:cc:0f:af:ed:c4:aa:5e:fa:40:52:3e:f1:11:db:e0";
    sshKey.fingerprintMD5 = "d6cc0fafedc4aa5efa40523ef111dbe0";
    sshKey.key = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC4tjz4mfMLvJsM8RXIgdRYPBhH//VXLXbeLb"
        + "UsJpm5ARIQPY6Gu1befPA3jqKacvdcBrMsYGiMp/DOhpkAwWclSnzMdvYLbYWkrOP"
        + "wBVrRh7lvFtXFLaQZ6do4uMZHb5zU2ViTFacrJ6zJ/GLltjk4nBea7Z4qHaQdWou3"
        + "Fk/108oMQGx7jqW44m+TA+HYo6rEbVWbimWVXyyiKchO2LTLKUbK6GBSWJiItezwA"
        + "WR3KKs3FXKRmbJDiKESh3mDccJidfkjzNLPyDf3JHI2b/C/mcvtJsoAtkIWuVll2B"
        + "hBBiqkYt3tX2llZCYGtF7rZOYTsqhw+LPnsJtsX+W7e4iN";
    SshKeyUtils.sshKeys.add(sshKey);

    sshKey = new SshKey();
    sshKey.fingerprintSHA256 = "dowJH1al1DJII+i7DYux1BGQkx3P+XVpaz3TIX5zt5Y=";
    sshKey.fingerprintMD5Formatted = "26:5a:f5:c5:56:42:1a:4e:94:32:f6:5e:48:b3:7d:91";
    sshKey.fingerprintMD5 = "265af5c556421a4e9432f65e48b37d91";
    sshKey.key = "AAAAB3NzaC1yc2EAAAABIwAAAQEAxL6nllg/rMURT2QTy4MGj0gxYQ6sxcqCde5or"
        + "LBs4rjIogo9bL7+HFLt6FHpCQbZ0CXakoL2M7PmXbFdwlD4Yw4ye4VxEaW3J1eNzR"
        + "MWMGNTaAlcGiQqDuS/SsxI6SOlp/kfXQprDn2MnED1jIQHQq5pm25wKpKYeUBAaC6"
        + "hvA4OlE39YpMCsVPEM3BhkR7F51I/60+5jV5P/g0arCnZKYJOnLmNpYc86ry8yydQ"
        + "MvD5HFBjRR8GRfvTU/0UcVtNsa1PzHTD7+lTA7iwDHX4cfe+4o38C850zU9yUMV+S"
        + "nlLMJhwBiCxaaqeU0SdBbG+nCL47drSlSvv85+baXftSw==";
    SshKeyUtils.sshKeys.add(sshKey);

  }
}
