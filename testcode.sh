#!/bin/bash
grep -r "electrum\/" electrum_mona
grep -r "import\ electrum " electrum_mona
grep -r "import\ electrum\." electrum_mona
grep -r "from\ electrum " electrum_mona
grep -r "from\ electrum\." electrum_mona
pytest electrum_mona/tests/
