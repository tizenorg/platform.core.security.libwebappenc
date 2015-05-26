Name:    libwebappenc
Summary: Web application encryption service
Version: 0.1.0
Release: 1
Group:   System/Libraries
License: Apache-2.0
Source0: %{name}-%{version}.tar.gz
Source1001: %{name}.manifest

Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig

BuildRequires: cmake
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(key-manager)
BuildRequires: pkgconfig(libtzplatform-config)
Requires: openssl
Requires: pkgconfig(libtzplatform-config)

%description
Web application encryption and decryption service

%package devel
Summary:    Web application encryption service (development files)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Web application encryption and decryption service (development files)

%package test
Summary:    Web application encryption service (test)
Group:      Development
Requires:   %{name} = %{version}-%{release}

%description test
Web application encryption and decryption service (test)



%prep
%setup -q
cp %{SOURCE1001} .

%build
%{!?build_type:%define build_type "Release"}
%cmake . -DPREFIX=%{_prefix} \
         -DEXEC_PREFIX=%{_exec_prefix} \
         -DINCLUDEDIR=%{_includedir} \
         -DLIBDIR=%{_libdir} \
         -DBINDIR=%TZ_SYS_BIN \
         -DSYSTEMD_UNIT_DIR=%{_unitdir} \
         -DCMAKE_BUILD_TYPE=%{build_type} \
         -DTZ_SYS_BIN=%TZ_SYS_BIN \
         -DTZ_SYS_SHARE=%TZ_SYS_SHARE

make %{?jobs:-j%jobs}


%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{TZ_SYS_SHARE}/license
cp LICENSE.Apache-2.0 %{buildroot}%{TZ_SYS_SHARE}/license/%{name}
%make_install
mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
ln -s ../webappenc-initializer.service %{buildroot}%{_unitdir}/multi-user.target.wants/webappenc-initializer.service


%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig
systemctl daemon-reload
if [ $1 = 1 ]; then
    # installation
    systemctl start webappenc-initializer.service
fi

if [ $1 = 2 ]; then
    # update
    systemctl restart webappenc-initializer.service
fi

%postun
/sbin/ldconfig
if [ $1 = 0 ]; then
    # uninstall
    systemctl daemon-reload
fi


%files
%defattr(-,root,root,-)
%manifest %{name}.manifest
%{TZ_SYS_SHARE}/license/%{name}
%{_libdir}/%{name}.so.*
%{_unitdir}/webappenc-initializer.service
%{_unitdir}/multi-user.target.wants/webappenc-initializer.service
%{TZ_SYS_BIN}/wae_initializer
%{TZ_SYS_SHARE}/wae/app_dek/WAE_APPDEK_KEK_PrivateKey.pem
%{TZ_SYS_SHARE}/wae/app_dek/WAE_APPDEK_KEK_PublicKey.pem

%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/pkgconfig/%{name}.pc
%{_libdir}/%{name}.so

%files test
%defattr(-,root,root,-)
%{TZ_SYS_BIN}/wae_tests


