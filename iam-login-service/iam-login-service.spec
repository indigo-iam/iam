%define user  iam
%define jdk_version  17
%define mvn_version  3.8.0

%{!?_unitdir: %global _unitdir %{_prefix}/lib/systemd/system}
%{!?base_version: %global base_version 0.0.0}

Name:      iam-login-service
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

%description
The INDIGO IAM (Identity and Access Management service) provides 
user identity and policy information to services so that consistent 
authorization decisions can be enforced across distributed services.

%prep

%build
mvn -U -B -DskipTests clean package

%install
install -d %{buildroot}/var/lib/indigo/%{name}
install -d %{buildroot}%{_sysconfdir}/%{name}/config
install -d %{buildroot}%{_sysconfdir}/sysconfig
install -d %{buildroot}/%{_unitdir}

install -m 644 "%{name}/target/%{name}.war" %{buildroot}/var/lib/indigo/%{name}/
install -m 644 "rpm/SOURCES/%{name}.service" %{buildroot}%{_unitdir}/
install -m 644 "rpm/SOURCES/%{name}" %{buildroot}%{_sysconfdir}/sysconfig/%{name}

%post
# Create service user if not exists
if ! getent passwd %{user} > /dev/null; then
    useradd --comment "INDIGO IAM" --system --user-group --home-dir /var/lib/indigo/%{name} --no-create-home --shell /sbin/nologin %{user}
fi

chown -R %{user}:%{user} /var/lib/indigo/%{name}
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service


%files
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%dir %{_sysconfdir}/sysconfig
%dir %{_sysconfdir}/%{name}
%dir %{_sysconfdir}/%{name}/config
%dir /var/lib/indigo
%dir /var/lib/indigo/%{name}
/var/lib/indigo/%{name}/%{name}.war
%{_unitdir}/%{name}.service

%changelog
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
