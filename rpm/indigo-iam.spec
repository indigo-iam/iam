%define user  iam
%define jdk_version  17
%define mvn_version  3.8.0
%define login_svc iam-login-service
%define voms_svc  iam-voms-aa

%{!?_unitdir: %global _unitdir %{_prefix}/lib/systemd/system}
%{!?base_version: %global base_version 0.0.0}

Name:      indigo-iam
Version:   %{base_version}
Release:   1%{?dist}
BuildRoot: %{_tmppath}/%{name}-%{version}-build
Summary:   INDIGO Identity and Access Management Service
Group:     Applications/Web
License:   Apache-2.0
URL:       https://github.com/indigoiam/iam

BuildArch: noarch

BuildRequires: java-%{jdk_version}-openjdk-devel
BuildRequires: maven >= %{mvn_version}

Requires:      java-%{jdk_version}-openjdk

%{?systemd_requires}
Requires(pre):     /usr/sbin/useradd


%description
The INDIGO IAM (Identity and Access Management service) provides 
user identity and policy information to services so that consistent 
authorization decisions can be enforced across distributed services.

%package login-service
Summary:   INDIGO Identity and Access Management Login Service
Requires: %{name} = %{version}
Obsoletes: iam-login-service <= 1.14.1

%description login-service
This package provides the main Indigo IAM login service.

%package voms-aa
Summary:   INDIGO Identity and Access Management VOMS-AA Service
Requires: %{name} = %{version}

%description voms-aa
This package provides the optional VOMS Attribute Authority service.

%prep

%build
mvn -U -B -DskipTests clean package

%check
#mvn -B test

%install
install -d %{buildroot}%{_sysconfdir}/sysconfig
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_datadir}/%{name}

# iam-login-service
install -d %{buildroot}%{_sysconfdir}/%{login_svc}/config
install -m 644 "%{login_svc}/target/%{login_svc}.war" %{buildroot}%{_datadir}/%{name}/%{login_svc}.war
install -m 644 "rpm/SOURCES/%{login_svc}.service" %{buildroot}%{_unitdir}/%{login_svc}.service
install -m 644 "rpm/SOURCES/%{login_svc}@.service" %{buildroot}%{_unitdir}/%{login_svc}@.service
install -m 644 "rpm/SOURCES/%{login_svc}" %{buildroot}%{_sysconfdir}/sysconfig/%{login_svc}
# iam-voms-aa
install -d %{buildroot}%{_sysconfdir}/%{voms_svc}/config
install -m 644 "%{voms_svc}/target/%{voms_svc}.jar" %{buildroot}%{_datadir}/%{name}/%{voms_svc}.jar
install -m 644 "rpm/SOURCES/%{voms_svc}.service" %{buildroot}%{_unitdir}/%{voms_svc}.service
install -m 644 "rpm/SOURCES/%{voms_svc}@.service" %{buildroot}%{_unitdir}/%{voms_svc}@.service
install -m 644 "rpm/SOURCES/%{voms_svc}" %{buildroot}%{_sysconfdir}/sysconfig/%{voms_svc}

%pre
getent group %{user} &>/dev/null || groupadd -r %{user}
getent passwd %{user} &>/dev/null || \
    /usr/sbin/useradd -r -g %{user} -s /sbin/nologin -c "INDIGO IAM" \
        -m -d /var/lib/indigo/%{name} %{user}
exit 0

%post login-service
for srv in %{login_svc}.service `systemctl | awk '/%{login_svc}@.*\.service/{print $1}'`;
do
  %systemd_post $srv
done

%preun login-service
for srv in %{login_svc}.service `systemctl | awk '/%{login_svc}@.*\.service/{print $1}'`;
do
  %systemd_preun $srv
done

%postun login-service
for srv in %{login_svc}.service `systemctl | awk '/%{login_svc}@.*\.service/{print $1}'`;
do
  %systemd_postun_with_restart $srv
done

%post voms-aa
for srv in %{voms_svc}.service `systemctl | awk '/%{voms_svc}@.*\.service/{print $1}'`;
do
  %systemd_post $srv
done

%preun voms-aa
for srv in %{voms_svc}.service `systemctl | awk '/%{voms_svc}@.*\.service/{print $1}'`;
do
  %systemd_preun $srv
done

%postun voms-aa
for srv in %{voms_svc}.service `systemctl | awk '/%{voms_svc}@.*\.service/{print $1}'`;
do
  %systemd_postun_with_restart $srv
done


%files
%dir %{_datadir}/%{name}

%files login-service
%config(noreplace) %attr(0600,iam,iam) %{_sysconfdir}/sysconfig/%{login_svc}
%dir %{_sysconfdir}/%{login_svc}/config
%{_datadir}/%{name}/%{login_svc}.war
%{_unitdir}/%{login_svc}.service
%{_unitdir}/%{login_svc}@.service

%files voms-aa
%config(noreplace) %attr(0600,iam,iam) %{_sysconfdir}/sysconfig/%{voms_svc}
%dir %{_sysconfdir}/%{voms_svc}
%dir %{_sysconfdir}/%{voms_svc}/config
%{_datadir}/%{name}/%{voms_svc}.jar
%{_unitdir}/%{voms_svc}.service
%{_unitdir}/%{voms_svc}@.service


%changelog
* Mon Jan 26 2026 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.13.4
- Release 1.13.4

* Tue Dec 9 2025 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.13.3
- Release 1.13.3

* Tue Nov 25 2025 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.13.2
- Release 1.13.2

* Thu Nov 20 2025 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.13.1
- Release 1.13.1

* Mon Nov 3 2025 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.13.0
- Release 1.13.0

* Wed Oct 8 2025 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.12.3
- Release 1.12.3

* Thu Aug 7 2025 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.12.2
- Release 1.12.2

* Mon Aug 4 2025 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.12.1
- Release 1.12.1

* Fri May 30 2025 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.12.0
- Release 1.12.0

* Wed May 28 2025 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.11.2
- Release 1.11.2

* Mon May 19 2025 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.11.1
- Release 1.11.1

* Mon Feb 3 2025 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.11.0
- Release 1.11.0

* Tue Oct 15 2024 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.10.2
- Release 1.10.2

* Thu Aug 22 2024 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.10.1
- Release 1.10.1

* Mon Aug 5 2024 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.10.0
- Release 1.10.0

* Thu Jun 6 2024 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.9.0
- Release 1.9.0

* Thu May 30 2024 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.8.4
- Release 1.8.4

* Thu Sep 21 2023 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.8.2p2
- Release 1.8.2p2

* Tue Jul 04 2023 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.8.2p1
- Release 1.8.2p1

* Tue Jul 04 2023 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.8.1p1
- Release 1.8.1p1

* Wed Dec 07 2022 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.8.0
- Release 1.8.0

* Thu Jul 28 2022 Enrico Vianello <enrico.vianello@cnaf.infn.it> 1.8.0
- WIP Release 1.8.0

* Fri Dec 03 2021 Andrea Ceccanti <andrea.ceccanti@cnaf.infn.it> 1.7.2
- Release 1.7.2

* Sat Sep 11 2021 Andrea Ceccanti <andrea.ceccanti@cnaf.infn.it> 1.7.1
- Release 1.7.1

* Tue Aug 31 2021 Andrea Ceccanti <andrea.ceccanti@cnaf.infn.it> 1.7.0
- Release 1.7.0

* Fri Dec 13 2019 Andrea Ceccanti <andrea.ceccanti@cnaf.infn.it> 1.6.0
- Release 1.6.0

* Thu Oct 31 2019 Andrea Ceccanti <andrea.ceccanti@cnaf.infn.it> 1.5.0
- Release 1.5.0

* Thu May 17 2018 Andrea Ceccanti <andrea.ceccanti@cnaf.infn.it> 1.4.0
- Release 1.4.0

* Thu Jan 25 2018 Marco Caberletti <marco.caberletti@cnaf.infn.it> 1.2.0
- Release 1.2.0

* Fri Sep 29 2017 Andrea Ceccanti <andrea.ceccanti@cnaf.infn.it> 1.1.0
- Release 1.1.0.

* Tue Aug 8 2017 Marco Caberletti <marco.caberletti@cnaf.infn.it> 1.0.0
- Release 1.0.0.

* Thu Apr 27 2017 Marco Caberletti <marco.caberletti@cnaf.infn.it> 0.6.0
- Initial IAM Login Service for Indigo 2.
