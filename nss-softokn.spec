%global nspr_version 4.10.6
%global nss_name nss
%global nss_util_version 3.15.1
%global unsupported_tools_directory %{_libdir}/nss/unsupported-tools
%global saved_files_dir %{_libdir}/nss/saved
%global prelink_conf_dir %{_sysconfdir}/prelink.conf.d/
%global dracut_modules_dir %{_datadir}/dracut/modules.d/05nss-softokn/


# Produce .chk files for the final stripped binaries
#
# NOTE: The LD_LIBRARY_PATH line guarantees shlibsign links
# against the freebl that we just built. This is necessary
# because the signing algorithm changed on 3.14 to DSA2 with SHA256
# whereas we previously signed with DSA and SHA1. We must keep this line
# until all mock platforms have been updated.
# After %%{__os_install_post} we would add
# export LD_LIBRARY_PATH=$RPM_BUILD_ROOT/%{_libdir}
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    export LD_LIBRARY_PATH=$RPM_BUILD_ROOT/%{_libdir} \
    $RPM_BUILD_ROOT/%{unsupported_tools_directory}/shlibsign -i $RPM_BUILD_ROOT/%{_lib}/libfreeblpriv3.so \
    $RPM_BUILD_ROOT/%{unsupported_tools_directory}/shlibsign -i $RPM_BUILD_ROOT/%{_lib}/libfreebl3.so \
    $RPM_BUILD_ROOT/%{unsupported_tools_directory}/shlibsign -i $RPM_BUILD_ROOT/%{_libdir}/libnssdbm3.so \
    $RPM_BUILD_ROOT/%{unsupported_tools_directory}/shlibsign -i $RPM_BUILD_ROOT/%{_libdir}/libsoftokn3.so \
%{nil}

Summary:          Network Security Services Softoken Module
Name:             nss-softokn
Version:          3.14.3
Release:          23.3%{?dist}
License:          MPLv2.0
URL:              http://www.mozilla.org/projects/security/pki/nss/
Group:            System Environment/Libraries
Requires:         nspr >= %{nspr_version}
Requires:         nss-util >= %{nss_util_version}
Requires:         nss-softokn-freebl%{_isa} >= %{version}-%{release}
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:    nspr-devel >= %{nspr_version}
BuildRequires:    nss-util-devel >= %{nss_util_version}
BuildRequires:    sqlite-devel
BuildRequires:    zlib-devel
BuildRequires:    pkgconfig
BuildRequires:    gawk
BuildRequires:    psmisc
BuildRequires:    perl

Source0:          %{name}-%{version}.tar.bz2
# The nss-softokn tar ball is a subset of nss-{version}-stripped.tar.bz2, 
# Therefore we use the nss-split-softokn.sh script to keep only what we need.
# Download the nss tarball via CVS from the nss project and follow these
# steps to make the tarball for nss-softokn out of the one for nss:
# cvs co nss
# cvs nss-softokn
# cp ../../nss/devel/${version}-stripped.tar.bz2  .
# sh ./nss-split-softokn.sh ${version}
# A file named {name}-{version}-stripped.tar.bz2 should appear
Source1:          nss-split-softokn.sh
Source2:          nss-softokn.pc.in
Source3:          nss-softokn-config.in
Source4:          nss-softokn-prelink.conf
Source5:          nss-softokn-dracut-install

Patch1:           add-relro-linker-option.patch
Patch2:           build-nss-softoken-only.patch
Patch3:           handle-old-or-new-system-sqlite.patch
Patch8:           softoken-minimal-test-dependencies.patch
# This patch uses the gcc-iquote dir option documented at
# http://gcc.gnu.org/onlinedocs/gcc/Directory-Options.html#Directory-Options
# to place the in-tree directories at the head of the list on list of directories
# to be searched for for header files. This ensures a build even when system freebl 
# headers are older. Such is the case when we are starting a major update.
# NSSUTIL_INCLUDE_DIR, after all, contains both util and freebl headers. 
# Once has been bootstapped the patch may be removed, but it doesn't hurt to keep it.
Patch9:           iquote.patch
# build against nss-util-3.15.1
Patch10: 	fix-conflicts-with-nss-util-3.15.1.patch
# Upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=857882
# This patch for freebl and softoken
Patch49:          mozbz857882-fbst.patch

# Patch related to CVE-2015-2730
# Upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=1125025
# from https://hg.mozilla.org/projects/nss/rev/2c05e861ce07
Patch102:         CheckForPeqQ-or-PnoteqQ-before-adding-P-and-Q.patch

# AEG GCM fixes from upstream
# Upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=853285
# nss and tests
# Fix AES GCM tests
Patch51:          gcm-tests.patch
# Add the test files for AES GCM Test Cases 1, 7, 13
Patch52:          gcm-tests-0-6-12.patch
# Nitpicks
Patch53:          gcm-nits.patch
# freebl and softoken
Patch55:          freebl-gcm.patch
# extra gcm syncronization with upstream
Patch66:          gcm-extras4freebl.patch
Patch67:          gcm-extras4softoken.patch
Patch68:          disable_hw_gcm.patch
# all.sh will display cpuinfo
Patch70:          cpuinfo.patch
Patch71:    skip-check-fork-in_GetFunctionList.patch
# Patch applied upstream for nss-3.16
# Upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=956082
Patch72:    p3-956082.patch

# updates for FIPS
Patch80: 	nss-softokn-3.14-fips-post.patch
Patch81:	nss-softokn-3.14-fips.patch
Patch82:	nss-softokn-fips-rem-old-test.patch

# updates to make sure FIPS and softoken nodepend all work.
Patch85:	nss-softokn-3.14-lowhash-test.patch


# update outside the crypto boundary
Patch86:	Bug-5867634-shlibsign-return-non-zero-on-failure.patch

# update inside the crypto boundary
# Upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=1064636
Patch87: cve-2014-1568-softokn.patch

#silence sig child calls
Patch88:	nss-softokn-3.14-block-sigchld.patch
Patch89:	nss-softokn-3.14-freebl-dyload.patch
Patch90:	nss-softokn-3.14-os-avx-test.patch

%description
Network Security Services Softoken Cryptographic Module

%package freebl
Summary:          Freebl library for the Network Security Services
Group:            System Environment/Base
Conflicts:        nss < 3.12.2.99.3-5
Conflicts:        prelink < 0.4.3

%description freebl
NSS Softoken Cryptographic Module Freelb Library

Install the nss-softokn-freebl package if you need the freebl 
library.

%package freebl-devel
Summary:          Header and Library files for doing development with the Freebl library for NSS
Group:            System Environment/Base
Provides:         nss-softokn-freebl-static%{_isa} = %{version}-%{release}
Requires:         nss-softokn-freebl%{?_isa} = %{version}-%{release}

%description freebl-devel
NSS Softoken Cryptographic Module Freelb Library Development Tools
This package supports special needs of some PKCS #11 module developers and
is otherwise considered private to NSS. As such, the programming interfaces
may change and the usual NSS binary compatibility commitments do not apply.
Developers should rely only on the officially supported NSS public API.

%package devel
Summary:          Development libraries for Network Security Services
Group:            Development/Libraries
Requires:         nss-softokn%{?_isa} = %{version}-%{release}
Requires:         nss-softokn-freebl-devel%{?_isa} = %{version}-%{release}
Requires:         nspr-devel >= %{nspr_version}
Requires:         nss-util-devel >= %{nss_util_version}
Requires:         pkgconfig
BuildRequires:    nspr-devel >= %{nspr_version}
BuildRequires:    nss-util-devel >= %{nss_util_version}

%description devel
Header and library files for doing development with Network Security Services.

%prep
%setup -q

%patch1 -p0 -b .relro
%patch2 -p0 -b .softokenonly
%patch3 -p0 -b .oldsqlite
%patch8 -p0 -b .tests
# activate if needed when doing a major update with new apis
%patch9 -p0 -b .iquote
%patch10 -p0 -b .conflicts
%patch49 -p0 -b .suiteb4fbst
pushd mozilla/security/nss
%patch51 -p1 -b .aesgcm1
%patch52 -p0 -b .aesgcm2
%patch53 -p1 -b .aesgcm3
%patch55 -p1 -b .aesgcm5
popd
%patch66 -p0 -b .sync
%patch67 -p0 -b .sync
%patch68 -p0 -b .hw_comp
%patch70 -p0 -b .cpuinfo
%patch71 -p0 -b .nocheckfork
%patch72 -p0 -b .1044666
%patch80 -p0 -b .fips-post
%patch81 -p0 -b .fips
%patch82 -p0 -b .fips-rem-old-tests
%patch85 -p0 -b .lowhash-test
%patch86 -p0 -b .5867634
%patch87 -p0 -b .cve_2014-1568
%patch88 -p0 -b .block_sigchld
%patch89 -p0 -b .freebl-dyload
%patch90 -p0 -b .os_avx_patch

pushd mozilla/security/nss
%patch102 -p1 -b .extra_check
popd

%build

FREEBL_NO_DEPEND=1
export FREEBL_NO_DEPEND

# Must export FREEBL_LOWHASH=1 for nsslowhash.h so that it gets
# copied to dist and the rpm install phase can find it
# This due of the upstream changes to fix
# https://bugzilla.mozilla.org/show_bug.cgi?id=717906
FREEBL_LOWHASH=1
export FREEBL_LOWHASH

#FREEBL_USE_PRELINK=1
#export FREEBL_USE_PRELINK

# Enable compiler optimizations and disable debugging code
BUILD_OPT=1
export BUILD_OPT

# Uncomment to disable optimizations
#RPM_OPT_FLAGS=`echo $RPM_OPT_FLAGS | sed -e 's/-O2/-O0/g'`
#export RPM_OPT_FLAGS

# Generate symbolic info for debuggers
XCFLAGS=$RPM_OPT_FLAGS
export XCFLAGS

PKG_CONFIG_ALLOW_SYSTEM_LIBS=1
PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1

export PKG_CONFIG_ALLOW_SYSTEM_LIBS
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS

NSPR_INCLUDE_DIR=`/usr/bin/pkg-config --cflags-only-I nspr | sed 's/-I//'`
NSPR_LIB_DIR=`/usr/bin/pkg-config --libs-only-L nspr | sed 's/-L//'`

export NSPR_INCLUDE_DIR
export NSPR_LIB_DIR

NSS_INCLUDE_DIR=`/usr/bin/pkg-config --cflags-only-I nss-util | sed 's/-I//'`
NSS_LIB_DIR=`/usr/bin/pkg-config --libs-only-L nss-util | sed 's/-L//'`

export NSS_INCLUDE_DIR
export NSS_LIB_DIR

NSS_USE_SYSTEM_SQLITE=1
export NSS_USE_SYSTEM_SQLITE

%ifarch x86_64 ppc64 ia64 s390x sparc64
USE_64=1
export USE_64
%endif

# freebl supports ecc
NSS_ENABLE_ECC=1
export NSS_ENABLE_ECC

# uncomment if the iquote patch is activated
export IN_TREE_FREEBL_HEADERS_FIRST=1

# Use only the basicutil subset for sectools.a
export NSS_BUILD_SOFTOKEN_ONLY=1

# Compile softokn plus needed support
%{__make} -C ./mozilla/security/coreconf
%{__make} -C ./mozilla/security/dbm
%{__make} -C ./mozilla/security/nss

# Set up our package file
# The nspr_version and nss_util_version globals used here
# must match the ones nss-softokn has for its Requires. 
%{__mkdir_p} ./mozilla/dist/pkgconfig
%{__cat} %{SOURCE2} | sed -e "s,%%libdir%%,%{_libdir},g" \
                          -e "s,%%prefix%%,%{_prefix},g" \
                          -e "s,%%exec_prefix%%,%{_prefix},g" \
                          -e "s,%%includedir%%,%{_includedir}/nss3,g" \
                          -e "s,%%NSPR_VERSION%%,%{nspr_version},g" \
                          -e "s,%%NSSUTIL_VERSION%%,%{nss_util_version},g" \
                          -e "s,%%SOFTOKEN_VERSION%%,%{version},g" > \
                          ./mozilla/dist/pkgconfig/nss-softokn.pc

SOFTOKEN_VMAJOR=`cat mozilla/security/nss/lib/softoken/softkver.h | grep "#define.*SOFTOKEN_VMAJOR" | awk '{print $3}'`
SOFTOKEN_VMINOR=`cat mozilla/security/nss/lib/softoken/softkver.h | grep "#define.*SOFTOKEN_VMINOR" | awk '{print $3}'`
SOFTOKEN_VPATCH=`cat mozilla/security/nss/lib/softoken/softkver.h | grep "#define.*SOFTOKEN_VPATCH" | awk '{print $3}'`

export SOFTOKEN_VMAJOR
export SOFTOKEN_VMINOR
export SOFTOKEN_VPATCH

%{__cat} %{SOURCE3} | sed -e "s,@libdir@,%{_libdir},g" \
                          -e "s,@prefix@,%{_prefix},g" \
                          -e "s,@exec_prefix@,%{_prefix},g" \
                          -e "s,@includedir@,%{_includedir}/nss3,g" \
                          -e "s,@MOD_MAJOR_VERSION@,$SOFTOKEN_VMAJOR,g" \
                          -e "s,@MOD_MINOR_VERSION@,$SOFTOKEN_VMINOR,g" \
                          -e "s,@MOD_PATCH_VERSION@,$SOFTOKEN_VPATCH,g" \
                          > ./mozilla/dist/pkgconfig/nss-softokn-config

chmod 755 ./mozilla/dist/pkgconfig/nss-softokn-config


%check

# Begin -- copied from the build section
FREEBL_NO_DEPEND=1
export FREEBL_NO_DEPEND

BUILD_OPT=1
export BUILD_OPT

%ifarch x86_64 ppc64 ia64 s390x sparc64 aarch64
USE_64=1
export USE_64
%endif

NSS_ENABLE_ECC=1
export NSS_ENABLE_ECC

# End -- copied from the build section

# find the kernel version of our build host
kernel_ver=`rpm -q --qf "%{VERSION}\n" kernel | sort -u -n | head -1` || 0.0.0
kernel_version=`echo $kernel_ver.0.0.0 | awk -F. '{ print $1 }'` || 0
kernel_major=`echo $kernel_ver.0.0.0 | awk -F. '{ print $2 }'` || 0
kernel_minor=`echo $kernel_ver.0.0.0 | awk -F. '{ print $3 }'` || 0

echo "Kernel version = $kernel_ver, v=$kernel_version, major=$kernel_major, minor=$kernel_minor"

# don't enable gcm for testing if build is running on a RHEL-5 system.
disable_hw_gcm=1
if [ $kernel_version -gt 2 ]; then
   disable_hw_gcm=0  # 3.0 or greater
elif [ $kernel_version -eq 2 ]; then
   if [ $kernel_major -gt 6 ]; then
      disable_hw_gcm=0  # 2.7 or greater
   elif [ $kernel_major -eq 6 ]; then
      if [ $kernel_minor -ge 32 ]; then
          disable_hw_gcm=0 # 2.6.32 or greater
	  # all other kernels are older and don't support avx
      fi
   fi
fi

if [ $disable_hw_gcm -ne 0 ]; then
NSS_DISABLE_HW_GCM=1
export NSS_DISABLE_HW_GCM
fi


# enable the following line to force a test failure
# find ./mozilla -name \*.chk | xargs rm -f

# Run test suite.

SPACEISBAD=`find ./mozilla/security/nss/tests | grep -c ' '` ||:
if [ $SPACEISBAD -ne 0 ]; then
  echo "error: filenames containing space are not supported (xargs)"
  exit 1
fi

rm -rf ./mozilla/tests_results
pushd ./mozilla/security/nss/tests/
# all.sh is the test suite script

# only run cipher tests for nss-softokn
%global nss_cycles "standard"
%global nss_tests "cipher lowhash"
%global nss_ssl_tests " "
%global nss_ssl_run " "

HOST=localhost DOMSUF=localdomain PORT=$MYRAND NSS_CYCLES=%{?nss_cycles} NSS_TESTS=%{?nss_tests} NSS_SSL_TESTS=%{?nss_ssl_tests} NSS_SSL_RUN=%{?nss_ssl_run} ./all.sh

popd

TEST_FAILURES=`grep -c FAILED ./mozilla/tests_results/security/localhost.1/output.log` || :
# test suite is failing on arm and has for awhile let's run the test suite but make it non fatal on arm
%ifnarch %{arm}
if [ $TEST_FAILURES -ne 0 ]; then
  echo "error: test suite returned failure(s)"
  exit 1
fi
echo "test suite completed"
%endif

%install

%{__rm} -rf $RPM_BUILD_ROOT

# There is no make install target so we'll do it ourselves.

%{__mkdir_p} $RPM_BUILD_ROOT/%{_includedir}/nss3
%{__mkdir_p} $RPM_BUILD_ROOT/%{_bindir}
%{__mkdir_p} $RPM_BUILD_ROOT/%{_libdir}
%{__mkdir_p} $RPM_BUILD_ROOT/%{_lib}
%{__mkdir_p} $RPM_BUILD_ROOT/%{unsupported_tools_directory}
%{__mkdir_p} $RPM_BUILD_ROOT/%{_libdir}/pkgconfig
%{__mkdir_p} $RPM_BUILD_ROOT/%{saved_files_dir}
%{__mkdir_p} $RPM_BUILD_ROOT/%{prelink_conf_dir}
%{__mkdir_p} $RPM_BUILD_ROOT/%{dracut_modules_dir}

%{__install} -m 644 %{SOURCE4} $RPM_BUILD_ROOT/%{prelink_conf_dir}
%{__install} -m 755 %{SOURCE5} $RPM_BUILD_ROOT/%{dracut_modules_dir}/install


# Copy the binary libraries we want
for file in libsoftokn3.so libnssdbm3.so
do
  %{__install} -p -m 755 mozilla/dist/*.OBJ/lib/$file $RPM_BUILD_ROOT/%{_libdir}
done

# Because libcrypt depends on libfreebl3.so, it is special
# so we install it in /lib{64}, keeping a symbolic link to it
# back in /usr/lib{64} to keep everyone else working
for file in libfreebl3.so libfreeblpriv3.so
do
  %{__install} -p -m 755 mozilla/dist/*.OBJ/lib/$file $RPM_BUILD_ROOT/%{_lib}
  ln -sf ../../%{_lib}/$file $RPM_BUILD_ROOT/%{_libdir}/$file
done

# Make sure chk files can be found in both places
for file in libfreeblpriv3.chk libfreebl3.chk
do
  ln -s ../../%{_lib}/$file $RPM_BUILD_ROOT/%{_libdir}/$file
done

# Copy the binaries we ship as unsupported
for file in bltest fipstest shlibsign
do
  %{__install} -p -m 755 mozilla/dist/*.OBJ/bin/$file $RPM_BUILD_ROOT/%{unsupported_tools_directory}
done

# Copy the include files we want
for file in mozilla/dist/public/nss/*.h
do
  %{__install} -p -m 644 $file $RPM_BUILD_ROOT/%{_includedir}/nss3
done

# Copy some freebl include files we also want
for file in blapi.h alghmac.h softoken.h
do
  %{__install} -p -m 644 mozilla/dist/private/nss/$file $RPM_BUILD_ROOT/%{_includedir}/nss3
done

# Copy the static freebl library
for file in libfreebl.a libsoftokn.a
do
%{__install} -p -m 644 mozilla/dist/*.OBJ/lib/$file $RPM_BUILD_ROOT/%{_libdir}
done

# Copy the package configuration files
%{__install} -p -m 644 ./mozilla/dist/pkgconfig/nss-softokn.pc $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/nss-softokn.pc
%{__install} -p -m 755 ./mozilla/dist/pkgconfig/nss-softokn-config $RPM_BUILD_ROOT/%{_bindir}/nss-softokn-config

%clean
%{__rm} -rf $RPM_BUILD_ROOT


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
%{_libdir}/libnssdbm3.so
%{_libdir}/libsoftokn3.so
%{_libdir}/libnssdbm3.chk
%{_libdir}/libsoftokn3.chk
# shared with nss-tools
%dir %{_libdir}/nss
%dir %{saved_files_dir}
%dir %{unsupported_tools_directory}
%{unsupported_tools_directory}/bltest
%{unsupported_tools_directory}/fipstest
%{unsupported_tools_directory}/shlibsign

%files freebl
%defattr(-,root,root)
/%{_lib}/libfreebl3.so
/%{_lib}/libfreebl3.chk
/%{_lib}/libfreeblpriv3.so
/%{_lib}/libfreeblpriv3.chk
# and these symbolic links
%{_libdir}/libfreebl3.so
%{_libdir}/libfreebl3.chk
%{_libdir}/libfreeblpriv3.so
%{_libdir}/libfreeblpriv3.chk
#shared
%dir %{prelink_conf_dir}
%{prelink_conf_dir}/nss-softokn-prelink.conf
%{dracut_modules_dir}
%{dracut_modules_dir}/install

%files freebl-devel
%defattr(-,root,root)
%{_libdir}/libfreebl.a
%{_libdir}/libsoftokn.a
%{_includedir}/nss3/blapi.h
%{_includedir}/nss3/blapit.h
%{_includedir}/nss3/alghmac.h
%{_includedir}/nss3/softoken.h

%files devel
%defattr(-,root,root)
%{_libdir}/pkgconfig/nss-softokn.pc
%{_bindir}/nss-softokn-config

# co-owned with nss
%dir %{_includedir}/nss3
#
# The following headers are those exported public in
# mozilla/security/nss/lib/freebl/manifest.mn and
# mozilla/security/nss/lib/softoken/manifest.mn
#
# The following list is short because many headers, such as
# the pkcs #11 ones, have been provided by nss-util-devel
# which installed them before us.
#
%{_includedir}/nss3/ecl-exp.h
%{_includedir}/nss3/nsslowhash.h
%{_includedir}/nss3/shsign.h

%changelog
* Mon May 23 2016 Elio Maldonado <emaldona@redhat.com> - 3.14.3-23.3
- Build using the proper RHEL-6.8-Z release target
- Resolves: Bug 1337821

* Fri May 20 2016 Elio Maldonado <emaldona@redhat.com> - 3.14.3-23.2
- Bump the release tag
- Turn off AVX if the OS (or VM) doesn't support it.
- Resolves: Bug 1337821

* Fri May 20 2016 Bob Relyea <rrelyea@redhat.com> - 3.14.3-23.1
- Turn off AVX if the OS (or VM) doesn't support it.
- Resolves: Bug 1337821

* Mon Aug 10 2015 Elio Maldonado <emaldona@redhat.com> - 3.14.3-23
- Pick up upstream freebl patch for CVE-2015-2730
- Check for P == Q or P ==-Q before adding P and Q

* Wed Jan 28 2015 Bob Relyea <rrelyea@redhat.com> - 3.14.3-22
- fix permissions on dracut install file.
- Resolves: Bug 1182297

* Fri Jan 16 2015 Bob Relyea <rrelyea@redhat.com> - 3.14.3-21
- Require nss-softokn-freebl of at least the same version and release
- Resolves: Bug 1182662 - nss-softokn-3.14.3-19.el6_6 breaking yum and rpm

* Thu Jan 08 2015 Bob Relyea <rrelyea@redhat.com> - 3.14.3-20
- keep a dummy libfreebl3.chk to keep dracut happy.

* Mon Dec 01 2014 Bob Relyea <rrelyea@redhat.com> - 3.14.3-19
- Resolves: Bug 1166921 - nss-softokn recent change causes application to segfault

* Thu Oct 22 2014 Bob Relyea <rrelyea@redhat.com> - 3.14.3-18
- Silent sigchld events

* Thu Sep 25 2014 Kai Engert <kaie@redhat.com> - 3.14.3-17
- Adjust patch to be compatible with legacy softokn API.
- Resolves: Bug 1145432 - CVE-2014-1568

* Tue Sep 23 2014 Elio Maldonado <emaldona@redhat.com> - 3.14.3-16
- Resolves: Bug 1145432 - CVE-2014-1568

* Thu Aug 07 2014 Elio Maldonado <emaldona@redhat.com> - 3.14.3-15
- Fix shlibsign to return non-zero on failure
- Resolves: Bug 587634 - shlibsign returns 0 although if fails

* Mon Jun 9 2014 Bob Relyea <rrelyea@redhat.com> - 3.14.3.14
- Final Fips review comments.

* Mon Apr 7 2014 Bob Relyea <rrelyea@redhat.com> - 3.14.3.13
- Fips review comments.

* Tue Mar 25 2014 Elio Maldonado <emaldona@redhat.com> - 3.14.3-12
- Avoid call to sdb_measureAccess in lib/softoken/sdb.c s_open if NSS_SDB_USE_CACHE is "yes" or "no"
- Resolves: Bug 1044666 - Can curl HTTPS requests make fewer access system calls?

* Tue Mar 25 2014 Elio Maldonado <emaldona@redhat.com> - 3.14.3-11
- Skip calls to CHECK_FORK in {C & NSC}_GetFunctionList
- Resolves: Bug 1053437 - Admin server segfault when configuration DS configured on SSL port

* Mon Mar 24 2014 Bob Relyea <rrelyea@redhat.com> - 3.14.3.10
- add fips precheck back into softokn.

* Tue Sep 24 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-9
- back out -fips package changes

* Fri Sep 20 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-8
- Enable new packaging but don't apply nss-fips-post.patch
- Related: rhbz#1008513 - Unable to login in fips mode

* Thu Sep 19 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-7
- Fix the PR_Access stub to actually access the correct permissions
- Resolves: rhbz#1008513 - Unable to login in fips mode
- Run the lowhash tests
- Require nspr-4.0.0 and nss-util-3.15.1

* Thu Sep 12 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-6
- create -fips packages 
- patch submitted by Bob Relyea <rrelyea@redhat.com>
- fix the script that splits softoken off from nss
- patch nss/cmd/lib/basicutil.c to build against nss-util-3.15.1
- Resolves: rhbz#993441 - NSS needs to conform to new FIPS standard. [rhel-6.5.0]

* Mon Jul 29 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-5
- Resolves: rhbz#976572 - Pick up various upstream GCM code fixes applied since nss-3.14.3 was released
- Display cpuifo as part of the tests and make NSS_DISABLE_HW_GCM the environment variable to test for
- When appling the patches use a backup file suffix that better describes the patch purpose

* Thu May 23 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-4
- Enable ECC support for suite b and add upstream fixes for aec gcm
- Use the unstripped upstream sources with ecc support
- Limit the ECC support to suite b
- Apply several upstream aes gcm fixes
- Rename macros EC_MIN_KEY_BITS and EC_MAX_KEY_BITS per upstream
- Resolves: rhbz#960208 - Enable ECC in nss-softoken
- Related: rhbz#919172

* Fri Apr 26 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-3
- Add patch to conditionally compile according to old or new sqlite api
- new is used on rhel-6 while rhel-5 uses old but we need the same code for both
- Resolves: rhbz#919172 - Rebase to nss-softokn 3.14.3 to fix the lucky-13 issue

* Tue Apr 09 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-2
- Revert to using a code patch for relro support
- Related: rhbz#919172

* Sun Mar 24 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-1
- Update to NSS_3_14_3_RTM
- Resolves: rhbz#919172 - Rebase to nss-softokn 3.14.3 to fix the lucky-13 issue
- Add export LD_LIBRARY_PATH=$RPM_BUILD_ROOT/%{_libdir} before the signing commands in __spec_install_post scriplet
  to ensure signing tool links with in-tree freebl so verification uses same algorithm as in signing
- Add %%check section to run the upstream crypto reqression test suite as per packaging guidelines
- Don't install sechash.h or secmodt.h which as per 3.14 are provided by nss-devel
- Update the licence to MPLv2.0

* Sat Mar 23 2013 Elio Maldonado - 3.12.9-12
- Bootstrapping of the builroot in preparation for rebase to 3.14.3
- Remove hasht.h from the %files devel list to prevent update conflicts with nss-util
- With 3.14.3 hasht.h will be provided by nss-util-devel
- Related: rhbz#919172 - rebase nss-softokn to 3.14.3

* Thu Oct 27 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-11
- Bug 748524 - On NSS_NoDB_Init don't try to open pkcs11.txt or secmod.db

* Mon Oct 24 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-10
- Bug 747053 - FIPS changes for NSS, more DRBG tests

* Tue Sep 27 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-9
- Add relro support for executables and shared libraries

* Mon Jul 25 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-8
- Include the patch

* Mon Jul 25 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-7
- Fix the tag

* Fri Jul 22 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-5
- Add partial RELRO support as a security enhancement

* Thu Jun 23 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-5
- Retagging to pick up latest patch - Resolves: rhbz#710298

* Thu Jun 23 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-4
- Resolves: rhbz#710298 - fix intel optimized aes code to handle case where input and ouput are in the same buffer

* Sun Feb 27 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-3
- Add requires nss-softokn-freebl-devel to devel

* Fri Feb 04 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-2
- Add headers for nss-softokn-freebl-devel and expand the description

* Mon Jan 17 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-1
- Update to 3.12.9
- Enable Intel AES Hardware optimizations

* Fri Oct 01 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-1
- Update to 3.12.8

* Thu Aug 26 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7-1.1
- Retagging to remove an obsolete file

* Thu Aug 26 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7-1
- Update to 3.12.7

* Thu Aug 05 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.4-19
- Turn off Intel AES optimizations

* Mon Jun 08 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-2.1
- Don't enable FIPS when CONFIG_CRYPTO_FIPS=n
- Fix typo in the package description
- Fix capitalization error in prelink conflict statement
- Require nspr 4.8.4

* Wed Apr 21 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.4-17
- Updated prelink patch

* Thu Apr 15 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.4-16
- allow prelink of softoken and freebl. Change the verify code to use
  prelink -u if prelink is installed. Fix by Robert Relyea

* Mon Jan 18 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.4-11
- Move libfreebl3.so and its .chk file to /lib{64} keeping
- symbolic links to them in /usr/lib{64} so as not break others

* Mon Jan 18 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.4-10.3
- fix broken global

* Sun Jan 17 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.4-10.2
- rebuilt for RHEL-6-test-build

* Fri Jan 15 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.4-10.1
- Update to 3.12.4, reenable installing and pick up fixes from F-12
* Thu Aug 19 2009 Elio Maldonado <emaldona@redhat.com> 3.12.3.99.3-8.1
- Disable installing until conflicts are relsoved
* Thu Aug 19 2009 Elio Maldonado <emaldona@redhat.com> 3.12.3.99.3-8
- Initial build
