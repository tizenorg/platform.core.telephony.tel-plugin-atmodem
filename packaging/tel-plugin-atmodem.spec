#sbs-git:slp/pkgs/t/tel-plugin-atmodem
Name: tel-plugin-atmodem
Summary: Telephony AT Modem library
Version: 0.1.40
Release:    1
Group:      System/Libraries
License:    Apache-2.0
Source0:    tel-plugin-atmodem-%{version}.tar.gz
Source1001: 	tel-plugin-atmodem.manifest
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(tcore)

%description
Telephony AT Modem library

%prep
%setup -q
cp %{SOURCE1001} .

%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}
make %{?jobs:-j%jobs}

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
rm -rf %{buildroot}
%make_install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
#%doc COPYING
%{_libdir}/telephony/plugins/modems/atmodem-plugin*
/tmp/mcc_mnc_oper_list.sql
/usr/share/license/%{name}
