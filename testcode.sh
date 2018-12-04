#!/bin/bash
grep -r "electrum\/" ../electrum-mona
grep -r "import\ electrum " ../electrum-mona
grep -r "import\ electrum\." ../electrum-mona
grep -r "from\ electrum " ../electrum-mona
grep -r "from\ electrum\." ../electrum-mona
pytest electrum_mona/tests/
