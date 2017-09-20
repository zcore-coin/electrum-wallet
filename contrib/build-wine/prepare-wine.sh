#!/bin/bash

# Please update these links carefully, some versions won't work under Wine
#PYTHON_URL=https://www.python.org/ftp/python/3.4.4/python-3.4.4.amd64.msi
PYTHON_URL=https://www.python.org/ftp/python/3.6.2/python-3.6.2.exe
#PYWIN32_URL=https://sourceforge.net/projects/pywin32/files/pywin32/Build%20221/pywin32-221.win-amd64-py3.4.exe
PYWIN32_URL=https://sourceforge.net/projects/pywin32/files/pywin32/Build%20221/pywin32-221.win32-py3.6.exe
#PYQT4_URL=https://sourceforge.net/projects/pyqt/files/PyQt4/PyQt-4.11.4/PyQt4-4.11.4-gpl-Py3.4-Qt4.8.7-x64.exe
PYQT4_URL=http://www.lfd.uci.edu/~gohlke/pythonlibs/hkfh9m5o/PyQt4-4.11.4-cp36-cp36m-win32.whl
PYINSTALLER_URL=https://github.com/pyinstaller/pyinstaller/archive/develop.zip
NSIS_URL=http://prdownloads.sourceforge.net/nsis/nsis-2.46-setup.exe?download
LYRA2RE_HASH_PYTHON_URL=https://github.com/metalicjames/lyra2re-hash-python/archive/master.zip


## These settings probably don't need change
export WINEPREFIX=/opt/wine64
#export WINEARCH='win32'

PYHOME=c:/python36
PYTHON="wine $PYHOME/python.exe -OO -B"

# Let's begin!
cd `dirname $0`
set -e

# Clean up Wine environment
echo "Cleaning $WINEPREFIX"
rm -rf $WINEPREFIX
echo "done"

wine 'wineboot'

echo "Cleaning tmp"
rm -rf tmp
mkdir -p tmp
echo "done"

cd tmp

# Install Python
wget -O python-3.6.2.exe "$PYTHON_URL"
wine python-3.6.2.exe /quiet TargetDir=C:\Python36 PrependPath=1

# Install PyWin32
wget -O pywin32.exe "$PYWIN32_URL"
wine pywin32.exe

# Install PyQt4
wget --user-agent="Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)" -O PyQt4-4.11.4-cp36-cp36m-win32.whl "$PYQT4_URL"
$PYTHON -m pip install PyQt4-4.11.4-cp36-cp36m-win32.whl

# upgrade pip
$PYTHON -m pip install pip --upgrade

# Install pyinstaller
$PYTHON -m pip install "$PYINSTALLER_URL"

# Install ZBar
#wget -q -O zbar.exe "http://sourceforge.net/projects/zbar/files/zbar/0.10/zbar-0.10-setup.exe/download"
#wine zbar.exe

# install Cryptodome
$PYTHON -m pip install pycryptodomex

# install PySocks
$PYTHON -m pip install win_inet_pton

# install websocket (python2)
$PYTHON -m pip install websocket-client


# Install setuptools
#wget -O setuptools.exe "$SETUPTOOLS_URL"
#wine setuptools.exe

# Upgrade setuptools (so Electrum can be installed later)
$PYTHON -m pip install setuptools --upgrade

# Install NSIS installer
echo "Make sure to untick 'Start NSIS' and 'Show release notes'" 
wget -q -O nsis.exe "$NSIS_URL"
wine nsis.exe

# Install UPX
#wget -O upx.zip "http://upx.sourceforge.net/download/upx308w.zip"
#unzip -o upx.zip
#cp upx*/upx.exe .

# add dlls needed for pyinstaller:
cp $WINEPREFIX/drive_c/windows/system32/msvcp90.dll $WINEPREFIX/drive_c/Python36/
cp $WINEPREFIX/drive_c/windows/system32/msvcm90.dll $WINEPREFIX/drive_c/Python36/


# Install MinGW
wget http://downloads.sourceforge.net/project/mingw/Installer/mingw-get-setup.exe
wine mingw-get-setup.exe

echo "add c:\MinGW\bin to PATH using regedit"
echo "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
regedit

wine mingw-get install gcc
wine mingw-get install mingw-utils
wine mingw-get install mingw32-libz

printf "[build]\ncompiler=mingw32\n" > $WINEPREFIX/drive_c/Python36/Lib/distutils/distutils.cfg

# build msvcr140.dll
cp ../msvcr140.patch $WINEPREFIX/drive_c/Python36/Lib/distutils
pushd $WINEPREFIX/drive_c/Python36/Lib/distutils
patch < msvcr140.patch
popd

wine mingw-get install pexports
wine pexports $WINEPREFIX/drive_c/Python36/vcruntime140.dll >vcruntime140.def
wine dlltool -dllname $WINEPREFIX/drive_c/Python36/vcruntime140.dll --def vcruntime140.def --output-lib libvcruntime140.a
cp libvcruntime140.a $WINEPREFIX/drive_c/MinGW/lib/

$PYTHON -m pip install $LYRA2RE_HASH_PYTHON_URL
