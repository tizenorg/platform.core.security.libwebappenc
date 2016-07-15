Name:    libwebappenc
Summary: Web application encryption service
Version: 0.1.0
Release: 1
Group:   Security/Libraries
License: Apache-2.0 and BSL-1.0
Source0: %{name}-%{version}.tar.gz

Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig

BuildRequires: cmake
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(key-manager)
BuildRequires: pkgconfig(libtzplatform-config)

%description
Web application encryption and decryption service

%package devel
Summary:    Web application encryption service (development files)
License:    Apache-2.0
Group:      Security/Development
Requires:   %{name} = %{version}-%{release}

%description devel
Web application encryption and decryption service (development files)

%package test
Summary:    Web application encryption service (test)
License:    Apache-2.0 and BSL-1.0
Group:      Security/Development
BuildRequires: boost-devel
Requires:      %{name} = %{version}-%{release}

%description test
Web application encryption and decryption service (test)

%define installer_label "User"
%define bin_dir         %TZ_SYS_BIN
%define rw_share_dir    %TZ_SYS_SHARE

%prep
%setup -q

%build
%{!?build_type:%define build_type "Release"}
%cmake . -DPREFIX=%{_prefix} \
         -DEXEC_PREFIX=%{_exec_prefix} \
         -DINCLUDEDIR=%{_includedir} \
         -DLIBDIR=%{_libdir} \
         -DSYSTEMD_UNIT_DIR=%{_unitdir} \
         -DCMAKE_BUILD_TYPE=%{build_type} \
         -DRW_SHARE_DIR=%rw_share_dir \
         -DBINDIR=%bin_dir \
         -DINSTALLER_LABEL=%installer_label

make %{?jobs:-j%jobs}

%install
%make_install
%install_service multi-user.target.wants webappenc-initializer.service

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
%manifest %{name}.manifest
%license LICENSE
%license LICENSE.BSL-1.0
%{_libdir}/%{name}.so.*
%{_unitdir}/webappenc-initializer.service
%{_unitdir}/multi-user.target.wants/webappenc-initializer.service
%{bin_dir}/wae_initializer
%{rw_share_dir}/wae/app_dek/WAE_APPDEK_KEK_PrivateKey.pem
%{rw_share_dir}/wae/app_dek/WAE_APPDEK_KEK_PublicKey.pem

%files devel
%{_includedir}/*
%{_libdir}/pkgconfig/%{name}.pc
%{_libdir}/%{name}.so

%files test
%manifest %{name}-test.manifest
%license LICENSE
%license LICENSE.BSL-1.0
%{bin_dir}/wae_tests
%{_libdir}/libwae_tests_common.so*
