#!/bin/bash

# You probably need to update only this link
ELECTRUM_GIT_URL=git://github.com/wakiyamap/electrum-mona.git
ELECTRUM_LOCALE_URL=git://github.com/spesmilo/electrum-locale.git
BRANCH=master
NAME_ROOT=electrum-mona
PYTHON_VERSION=3.6.3

if [ "$#" -gt 0 ]; then
    BRANCH="$1"
fi

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=22

PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"


# Let's begin!
cd `dirname $0`
set -e

cd tmp


if [ -d "electrum-mona" ]; then
    # GIT repository found, update it
    echo "Pull"
    cd electrum-mona
    git checkout $BRANCH
    git pull
    cd ..
else
    # GIT repository not found, clone it
    echo "Clone"
    git clone -b $BRANCH $ELECTRUM_GIT_URL electrum-mona
fi

if [ -d "electrum-locale" ]; then
    # GIT repository found, update it
    echo "Pull"
    cd electrum-locale
    git checkout $BRANCH
    git pull
    cd ..
else
    # GIT repository not found, clone it
    echo "Clone"
    git clone -b $BRANCH $ELECTRUM_LOCALE_URL electrum-locale
fi

pushd electrum-locale
for i in ./locale/*; do
    dir=$i/LC_MESSAGES
    mkdir -p $dir
    msgfmt --output-file=$dir/electrum.mo $i/electrum.po || true
done
popd

pushd electrum-mona
if [ ! -z "$1" ]; then
    git checkout $1
fi

VERSION=`git describe --tags`
echo "Last commit: $VERSION"
popd

rm -rf $WINEPREFIX/drive_c/electrum-mona
cp -r electrum-mona $WINEPREFIX/drive_c/electrum-mona
cp electrum-mona/LICENCE .
cp -r electrum-locale/locale $WINEPREFIX/drive_c/electrum-mona/lib/
# Build Qt resources
wine $WINEPREFIX/drive_c/python$PYTHON_VERSION/Scripts/pyrcc5.exe C:/electrum-mona/icons.qrc -o C:/electrum-mona/gui/qt/icons_rc.py

# Build target
pushd $WINEPREFIX/drive_c/electrum-mona/lib
$PYTHON setup.py build_ext --inplace
cp $WINEPREFIX/drive_c/electrum-mona/lib/lib/target.*.pyd $WINEPREFIX/drive_c/python$PYTHON_VERSION/
popd

# build japanese version
cp ../default-ja.patch $WINEPREFIX/drive_c/electrum-mona/gui/qt
pushd $WINEPREFIX/drive_c/electrum-mona/gui/qt
patch < default-ja.patch
popd

# Install frozen dependencies
$PYTHON -m pip install -r ../../requirements.txt

pushd $WINEPREFIX/drive_c/electrum-mona
$PYTHON setup.py install
popd

cd ..

rm -rf dist/

# build standalone and portable versions
wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --name $NAME_ROOT-$VERSION -w deterministic.spec

# set timestamps in dist, in order to make the installer reproducible
pushd dist
find  -type f  -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

# build NSIS installer
# $VERSION could be passed to the electrum.nsi script, but this would require some rewriting in the script iself.
if [ -d "$WINEPREFIX/drive_c/Program Files (x86)" ]; then
    wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" /DPRODUCT_VERSION=$VERSION electrum.nsi
else
    wine "$WINEPREFIX/drive_c/Program Files/NSIS/makensis.exe" /DPRODUCT_VERSION=$VERSION electrum.nsi
fi

cd dist
mv electrum-mona-setup.exe $NAME_ROOT-$VERSION-setup.exe
cd ..

echo "Done."
md5sum dist/electrum*exe
