%define major 0
%define minor 1
%define patchlevel 67

Name:              tel-plugin-atmodem
Version:           %{major}.%{minor}.%{patchlevel}
Release:           1
License:           Apache-2.0
Summary:           Telephony AT Modem library
Group:             System/Libraries
Source0:           tel-plugin-atmodem-%{version}.tar.gz
BuildRequires:     cmake
BuildRequires:     pkgconfig(glib-2.0)
BuildRequires:     pkgconfig(dlog)
BuildRequires:     pkgconfig(tcore)
Requires(post):    /sbin/ldconfig
Requires(postun):  /sbin/ldconfig

%description
Telephony AT Modem library

%prep
%setup -q

%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-DLIB_INSTALL_DIR=%{_libdir}
make %{?_smp_mflags}

%post
/sbin/ldconfig

%postun -p /sbin/ldconfig

%install
%make_install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%files
%manifest tel-plugin-atmodem.manifest
%defattr(644,system,system,-)
#%doc COPYING
%{_libdir}/telephony/plugins/modems/atmodem-plugin*
/usr/share/license/%{name}
