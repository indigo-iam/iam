FROM jtgasper3/centos-shibboleth-sp

RUN yum -y update \
    && yum -y install php mod_ssl

COPY etc-shibboleth /etc/shibboleth/
COPY etc-httpd/ /etc/httpd/
COPY var-www-html/ /var/www/html/

RUN chmod +x /etc/shibboleth/shibd-redhat
