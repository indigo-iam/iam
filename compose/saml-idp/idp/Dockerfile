FROM unicon/shibboleth-idp:latest

MAINTAINER Unicon, Inc.

COPY shibboleth-idp/ /opt/shibboleth-idp/

#Testing JCE code as well (from base image's readme)
RUN yum -y update \
    && yum -y install unzip \
    && mkdir -p /opt/jre-home/jre/lib/security \
    && wget --no-check-certificate --no-cookies --header "Cookie: oraclelicense=accept-securebackup-cookie" \
    http://download.oracle.com/otn-pub/java/jce/8/jce_policy-8.zip \
    && echo "f3020a3922efd6626c2fff45695d527f34a8020e938a49292561f18ad1320b59  jce_policy-8.zip" | sha256sum -c - \
    && unzip -oj jce_policy-8.zip UnlimitedJCEPolicyJDK8/local_policy.jar -d /opt/jre-home/jre/lib/security/ \
    && unzip -oj jce_policy-8.zip UnlimitedJCEPolicyJDK8/US_export_policy.jar -d /opt/jre-home/jre/lib/security/ \
    && rm jce_policy-8.zip \
    && chmod -R 640 /opt/jre-home/jre/lib/security/ \
    && chown -R root:jetty /opt/jre-home/jre/lib/security/   
