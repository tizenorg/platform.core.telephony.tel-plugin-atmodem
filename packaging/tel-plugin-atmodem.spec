%define major 0
%define minor 1
%define patchlevel 57

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

mkdir -p /opt/dbspace

if [ ! -f /opt/dbspace/.mcc_mnc_oper_list.db ]
then
	sqlite3 /opt/dbspace/.mcc_mnc_oper_list.db < /tmp/mcc_mnc_oper_list.sql
fi

rm -f /tmp/mcc_mnc_oper_list.sql

if [ -f /opt/dbspace/.mcc_mnc_oper_list.db ]
then
chmod 600 /opt/dbspace/.mcc_mnc_oper_list.db
fi

if [ -f /opt/dbspace/.mcc_mnc_oper_list.db-journal ]
then
chmod 644 /opt/dbspace/.mcc_mnc_oper_list.db-journal
fi

%postun -p /sbin/ldconfig

%install
%make_install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%files
%manifest tel-plugin-atmodem.manifest
%defattr(-,root,root,-)
#%doc COPYING
%{_libdir}/telephony/plugins/modems/atmodem-plugin*
/tmp/mcc_mnc_oper_list.sql
/usr/share/license/%{name}
