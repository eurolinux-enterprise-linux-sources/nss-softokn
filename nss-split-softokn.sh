#!/bin/sh
#
# Splits NSS into nss-util and nss-softokn
# Takes as command line input the version of nss
# and assumes that a file nss-${nss_version}-stripped.tar.bz2
# exits in the current directory

set -e

if test -z $1
then
  echo "usage: $0 nss-version"
  exit
fi

export name=nss
export version=$1

echo "Extracting ${name}-${version}.tar.bz2"

tar -xjf ${name}-${version}.tar.bz2

# the directory will be named ${name}-${version}

nss_source_dir=${name}-${version}
softokn_dir=${name}-softokn-${version}

# make_nss_softokn
#-------------------------------------------------
# create the nss-softokn subset consisting of
#   mozilla/dbm                      --- full directory
#   mozilla/security                 --- top empty
#   mozilla/security/coreconf        --- full directory
#   mozilla/security/nss             --- top files only
#   mozilla/security/nss/lib         --- top files only
#   mozilla/security/nss/lib/freebl  --- full directory
#   mozilla/security/nss/lib/softoken --- full directory
#   mozilla/security/nss/lib/softoken/dbm --- full directory
#-------------------------------------------------------

SOFTOKN_WORK=${softokn_dir}-work
rm -rf ${SOFTOKN_WORK}
mkdir ${SOFTOKN_WORK}

# copy everything
cp -a ${nss_source_dir} ${SOFTOKN_WORK}/${softokn_dir}

# remove subdirectories that we don't want
rm -rf ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/cmd
rm -rf ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/tests
rm -rf ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/lib
rm -rf ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/pkg
# rstart with an empty lib directory and copy only what we need
mkdir ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/lib
# copy the top files from mozilla/security/nss/lib/
topFilesL=`find ${nss_source_dir}/mozilla/security/nss/lib/ -maxdepth 1 -mindepth 1 -type f`
for f in $topFilesL; do
  cp -p $f ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/lib
done
mkdir ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/lib/util
# copy entire freebl and softoken directories recursively
cp -a ${nss_source_dir}/mozilla/security/nss/lib/freebl ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/lib/freebl
cp -a ${nss_source_dir}/mozilla/security/nss/lib/softoken ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/lib/softoken

# and some Makefiles and related files from mozilla/security/nss
topFilesN=`find ${nss_source_dir}/mozilla/security/nss/ -maxdepth 1 -mindepth 1 -type f`
for f in $topFilesN; do
  cp -p $f ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/
done

# we do need shlibsign from cmd and also bltest, lib, and lowhashtest
mkdir ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/cmd
# copy some files at the top and the slhlib subdirectory
topFilesC=`find ${nss_source_dir}/mozilla/security/nss/cmd/ -maxdepth 1 -mindepth 1 -type f`
for f in $topFilesC; do
  cp -p $f ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/cmd/
done

cp -a ${nss_source_dir}/mozilla/security/nss/cmd/bltest ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/cmd/bltest
cp -a ${nss_source_dir}/mozilla/security/nss/cmd/fipstest ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/cmd/fipstest
cp -a ${nss_source_dir}/mozilla/security/nss/cmd/lib ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/cmd/lib
cp -a ${nss_source_dir}/mozilla/security/nss/cmd/lowhashtest ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/cmd/lowhashtest
cp -a ${nss_source_dir}/mozilla/security/nss/cmd/shlibsign ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/cmd/shlibsign

# plus common and crypto from mozilla/security/nss/tests
mkdir ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/tests
topFilesT=`find ${nss_source_dir}/mozilla/security/nss/tests/ -maxdepth 1 -mindepth 1 -type f`
for f in $topFilesT; do
  cp -p $f ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/tests/
done
keepers="cipher common"
for t in $keepers; do
  cp -a ${nss_source_dir}/mozilla/security/nss/tests/$t ${SOFTOKN_WORK}/${softokn_dir}/mozilla/security/nss/tests/$t
done

pushd ${SOFTOKN_WORK}
# the compressed tar ball for nss-softokn
tar -cjf ../${name}-softokn-${version}.tar.bz2 ${softokn_dir}
popd

# cleanup after ourselves
rm -fr ${nss_source_dir}
rm -rf ${SOFTOKN_WORK}



