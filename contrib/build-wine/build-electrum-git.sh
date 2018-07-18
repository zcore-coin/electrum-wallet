#!/bin/bash

NAME_ROOT=electrum-mona
PYTHON_VERSION=3.6.6

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=22

PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"


# Let's begin!
cd `dirname $0`
set -e

mkdir -p tmp
cd tmp

pushd $WINEPREFIX/drive_c/electrum-mona

# Load electrum-icons and electrum-locale for this release
git submodule init
git submodule update

VERSION=`git describe --tags --dirty`
echo "Last commit: $VERSION"

pushd ./contrib/deterministic-build/electrum-locale
if ! which msgfmt > /dev/null 2>&1; then
    echo "Please install gettext"
    exit 1
fi
for i in ./locale/*; do
    dir=$i/LC_MESSAGES
    mkdir -p $dir
    msgfmt --output-file=$dir/electrum.mo $i/electrum.po || true
done
popd

find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

cp $WINEPREFIX/drive_c/electrum-mona/LICENCE .
cp -r $WINEPREFIX/drive_c/electrum-mona/contrib/deterministic-build/electrum-locale/locale $WINEPREFIX/drive_c/electrum-mona/electrum/
cp $WINEPREFIX/drive_c/electrum-mona/contrib/deterministic-build/electrum-icons/icons_rc.py $WINEPREFIX/drive_c/electrum-mona/electrum/gui/qt/

# Install frozen dependencies
$PYTHON -m pip install -r ../../deterministic-build/requirements.txt

$PYTHON -m pip install -r ../../deterministic-build/requirements-hw.txt

pushd $WINEPREFIX/drive_c/electrum-mona
$PYTHON setup.py install
popd

cd ..

rm -rf dist/

# build standalone and portable versions
wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --clean --name $NAME_ROOT-$VERSION -w deterministic.spec

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
