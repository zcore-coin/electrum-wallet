#!/bin/bash

PYTHON_VERSION=3.6.3
# Please update these links carefully, some versions won't work under Wine
PYTHON_URL=https://www.python.org/ftp/python/$PYTHON_VERSION/python-$PYTHON_VERSION.exe
NSIS_URL=http://prdownloads.sourceforge.net/nsis/nsis-3.02.1-setup.exe?download
NSIS_SHA256=736c9062a02e297e335f82252e648a883171c98e0d5120439f538c81d429552e
VC2015_URL=https://download.microsoft.com/download/9/3/F/93FCF1E7-E6A4-478B-96E7-D4B285925B00/vc_redist.x86.exe
WINETRICKS_MASTER_URL=https://raw.githubusercontent.com/Winetricks/winetricks/master/src/winetricks
LYRA2RE_HASH_PYTHON_URL=https://github.com/metalicjames/lyra2re-hash-python/archive/master.zip

## These settings probably don't need change
export WINEPREFIX=/opt/wine64
#export WINEARCH='win32'

PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"


verify_hash() {
    local file=$1 expected_hash=$2 out=
    actual_hash=$(sha256sum $file | awk '{print $1}')
    if [ "$actual_hash" == "$expected_hash" ]; then
        return 0
    else
        echo "$file $actual_hash (unexpected hash)" >&2
        exit 0
    fi
}

# Let's begin!
cd `dirname $0`
set -e

# Clean up Wine environment
echo "Cleaning $WINEPREFIX"
#rm -rf $WINEPREFIX
echo "done"

wine 'wineboot'

echo "Cleaning tmp"
#rm -rf tmp
#mkdir -p tmp
echo "done"


cd tmp

# Install MinGW
#wget http://downloads.sourceforge.net/project/mingw/Installer/mingw-get-setup.exe
#wine mingw-get-setup.exe

echo "add C:\MinGW\bin to PATH using regedit"
echo "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
#regedit

#wine mingw-get install gcc
#wine mingw-get install mingw-utils
#wine mingw-get install mingw32-libz

#printf "[build]\ncompiler=mingw32\n" > $WINEPREFIX/drive_c/python$PYTHON_VERSION/Lib/distutils/distutils.cfg

# Install VC++2015
#wget -O vc_redist.x86.exe "$VC2015_URL"
#wine vc_redist.x86.exe /quiet
#wget $WINETRICKS_MASTER_URL
#bash winetricks vcrun2015

# build msvcr140.dll
#cp ../msvcr140.patch $WINEPREFIX/drive_c/python$PYTHON_VERSION/Lib/distutils
#pushd $WINEPREFIX/drive_c/python$PYTHON_VERSION/Lib/distutils
#patch < msvcr140.patch
#popd

#wine mingw-get install pexports
#wine pexports $WINEPREFIX/drive_c/python$PYTHON_VERSION/vcruntime140.dll >vcruntime140.def
#wine dlltool -dllname $WINEPREFIX/drive_c/python$PYTHON_VERSION/vcruntime140.dll --def vcruntime140.def --output-lib libvcruntime140.a
#cp libvcruntime140.a $WINEPREFIX/drive_c/MinGW/lib/

# install lyra2re2_hash
#$PYTHON -m pip install $LYRA2RE_HASH_PYTHON_URL

# install scrypt
wget https://pypi.python.org/packages/ec/8f/89ee71b476225707a5c84b78545e0af837d275fd863d7a41c1444191822f/scrypt-0.8.0-cp35-cp35m-win32.whl#md5=e564ba7b8f8b9b26552edcf6cc2789d1
$PYTHON -m pip install scrypt-0.8.0-cp35-cp35m-win32.whl


