Name: sailfish-connman-vpn-plugin-proto-test
Version: 0.0.2
Release: 0
Summary: Sailfish Connman external VPN plugin proto
Group: Development/Libraries
License: GPLv2
URL: https://github.com/LaakkonenJussi/sailfish-connman-vpn-plugin-proto
Source: %{name}-%{version}.tar.bz2
Requires: connman >= 1.32
Requires: glib2 >= 2.28
Requires: dbus >= 1.4
BuildRequires: connman-devel >= 1.32
BuildRequires: pkgconfig(glib-2.0) >= 2.28
BuildRequires: pkgconfig(dbus-1) >= 1.4
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
This package contains a prototype of Sailfish ConnMan external VPN plugin. This
is a clone from OpenVPN plugin from ConnMan and contains only the plugin
content, openvpn-script is not included.

%prep
%setup -q -n %{name}-%{version}

%build
make %{?_smp_mflags} release

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/%{_libdir}/connman/plugins-vpn

%preun

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/connman/plugins-vpn/*.so
