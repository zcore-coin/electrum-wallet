#!/bin/bash
grep -r "electrum\/" electrum_mona | grep -v "electrum\_mona\/locale"
grep -r "import\ electrum " electrum_mona | grep -v "electrum\_mona\/locale"
grep -r "import\ electrum\." electrum_mona | grep -v "electrum\_mona\/locale"
grep -r "from\ electrum " electrum_mona | grep -v "electrum\_mona\/locale"
grep -r "from\ electrum\." electrum_mona | grep -v "electrum\_mona\/locale"
grep -r "electrum\.gui" electrum_mona | grep -v "electrum\_mona\/locale"
pytest electrum_mona/tests/
