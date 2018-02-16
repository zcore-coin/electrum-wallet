#!/bin/bash

# You probably need to update only this link
ELECTRUM_GIT_URL=git://github.com/wakiyamap/electrum-mona.git
ELECTRUM_LOCALE_URL=git://github.com/spesmilo/electrum-locale.git
ELECTRUM_ICONS_URL=git://github.com/wakiyamap/electrum-icons.git
BRANCH=master
NAME_ROOT=electrum-mona
PYTHON_VERSION=3.6.4

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

if [ -d "electrum-icons" ]; then
    # GIT repository found, update it
    echo "Pull"
    cd electrum-icons
    #git checkout $BRANCH
    git pull
    cd ..
else
    # GIT repository not found, clone it
    echo "Clone"
    git clone -b $BRANCH $ELECTRUM_ICONS_URL electrum-icons
fi

if [ -d "electrum-locale" ]; then
    # GIT repository found, update it
    echo "Pull"
    cd electrum-locale
    #git checkout $BRANCH
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
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

rm -rf $WINEPREFIX/drive_c/electrum-mona
cp -r electrum-mona $WINEPREFIX/drive_c/electrum-mona
cp electrum-mona/LICENCE .
cp -r electrum-locale/locale $WINEPREFIX/drive_c/electrum-mona/lib/
cp electrum-icons/icons_rc.py $WINEPREFIX/drive_c/electrum-mona/gui/qt/

# Install frozen dependencies
$PYTHON -m pip install -r ../../deterministic-build/requirements.txt

# Workaround until they upload binary wheels themselves:
$PYTHON -m pip install https://github.com/wakiyamap/pyblake2/releases/download/temp/pyblake2-1.1.0-cp36-cp36m-win32.whl

$PYTHON -m pip install -r ../../deterministic-build/requirements-hw.txt

pushd $WINEPREFIX/drive_c/electrum-mona
$PYTHON setup.py install
popd

cd ..

rm -rf dist/

# build standalone and portable versions
wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --name $NAME_ROOT-$VERSION -w deterministic.spec

# set timestamps in dist, in order to make the installer reproducible
pushd dist
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
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
