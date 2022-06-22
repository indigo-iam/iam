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
package it.infn.mw.voms.aa;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VOMSNamingScheme {

  public static final Logger LOG = LoggerFactory.getLogger(VOMSNamingScheme.class);

  public static final String CONTAINER_SYNTAX =
      "^(/[\\w.-]+)+|((/[\\w.-]+)+/)?(Role=[\\w.-]+)|(Capability=[\\w\\s.-]+)$";

  public static final String GROUP_SYNTAX = "^(/[\\w.-]+)+$";

  public static final String ROLE_SYNTAX = "^Role=[\\w.-]+$";

  public static final String QUALIFIED_ROLE_SYNTAX = "^(/[\\w.-]+)+/Role=[\\w.-]+$";

  public static final String CAPABILITY_SYNTAX = "^Capability=[\\w\\s.-]+$";

  public static final Pattern CONTAINER_PATTERN = Pattern.compile(CONTAINER_SYNTAX);

  public static final Pattern GROUP_PATTERN = Pattern.compile(GROUP_SYNTAX);

  public static final Pattern ROLE_PATTERN = Pattern.compile(ROLE_SYNTAX);

  public static final Pattern QUALIFIED_ROLE_PATTERN = Pattern.compile(QUALIFIED_ROLE_SYNTAX);

  public static final Pattern CAPABILITY_PATTERN = Pattern.compile(CAPABILITY_SYNTAX);

  private VOMSNamingScheme() {
    // prevent instantiation
  }

  public static void basicFqanChecks(String fqan) {

    if (fqan == null) {
      throw new NullPointerException("fqan ==  null");
    }

    if (fqan.length() > 255)
      throw new VOMSNamingException("fqan.length() > 255");

    if (!CONTAINER_PATTERN.matcher(fqan).matches())
      throw new VOMSNamingException("Syntax error in container name: " + fqan);
  }

  public static void checkGroup(String groupName) {

    basicFqanChecks(groupName);

    if (!GROUP_PATTERN.matcher(groupName).matches()) {
      throw new VOMSNamingException("Syntax error in group name: " + groupName);
    }
  }

  public static void checkRole(String roleName) {

    if (roleName == null) {
      throw new NullPointerException("roleName == null");
    }

    if (roleName.length() > 255) {
      throw new VOMSNamingException("roleName.length()>255");
    }

    if (!ROLE_PATTERN.matcher(roleName).matches()) {
      throw new VOMSNamingException("Syntax error in role name: " + roleName);
    }
  }

  public static String getParentGroupName(String groupName) {

    basicFqanChecks(groupName);

    if (StringUtils.countMatches(groupName, "/") == 1) {
      return groupName;
    }
    return StringUtils.substringBeforeLast(groupName, "/");
  }

  public static String[] getParentGroupChain(String groupName) {

    basicFqanChecks(groupName);

    String[] tmp = groupName.split("/");
    String[] groupChain = ArrayUtils.subarray(tmp, 1, tmp.length);

    if (groupChain.length == 1) {
      return new String[] {groupName};
    }

    String[] result = new String[groupChain.length - 1];

    if (result.length == 1) {
      result[0] = "/" + groupChain[0];
      return result;
    }

    for (int i = groupChain.length - 1; i > 0; i--)
      result[i - 1] = "/" + StringUtils.join(ArrayUtils.subarray(groupChain, 0, i), "/");

    return result;
  }

  public static boolean isGroup(String groupName) {

    basicFqanChecks(groupName);
    return GROUP_PATTERN.matcher(groupName).matches();

  }

  public static boolean isValidGroupForVo(String voName, String fqan) {
    basicFqanChecks(fqan);

    if (!fqan.startsWith(voName)) {
      return false;
    }

    return GROUP_PATTERN.matcher(fqan).matches();
  }

  public static boolean isRole(String fqan) {

    basicFqanChecks(fqan);
    return ROLE_PATTERN.matcher(fqan).matches();
  }

  public static boolean isQualifiedRole(String fqan) {

    basicFqanChecks(fqan);
    return QUALIFIED_ROLE_PATTERN.matcher(fqan).matches();
  }

  public static Optional<String> getRoleName(String fqan) {

    if (!isRole(fqan) && !isQualifiedRole(fqan)) {
      return Optional.empty();
    }

    Matcher m = CONTAINER_PATTERN.matcher(fqan);

    if (m.matches()) {
      String roleGroup = m.group(4);
      return Optional.of(roleGroup.substring(roleGroup.indexOf('=') + 1, roleGroup.length()));
    }

    return Optional.empty();
  }


  public static Optional<String> getGroupName(String fqan) {

    basicFqanChecks(fqan);

    if (!isRole(fqan) && !isQualifiedRole(fqan))
      return Optional.of(fqan);

    Matcher m = CONTAINER_PATTERN.matcher(fqan);

    if (m.matches()) {
      String groupName = m.group(2);

      if (groupName.endsWith("/")) {
        return Optional.of(groupName.substring(0, groupName.length() - 1));
      } else {
        return Optional.of(groupName);
      }
    }

    return Optional.empty();
  }
}
