#!/bin/bash
grep -rI "electrum\/" ../electrum-mona . 2> /dev/null | grep -v -e "\/locale\/" -e "README" -e "RELEASE-NOTES" -e "electrum\/{version\.ELECTRUM\_VERSION}" -e "\/issues\/4994"
grep -rI "import\ electrum " ../electrum-mona . 2> /dev/null | grep -v -e "\/locale\/" -e "README" -e "RELEASE-NOTES" -e "electrum\/{version\.ELECTRUM\_VERSION}" -e "\/issues\/4994"
grep -rI "import\ electrum\." ../electrum-mona . 2> /dev/null | grep -v -e "\/locale\/" -e "README" -e "RELEASE-NOTES" -e "electrum\/{version\.ELECTRUM\_VERSION}" -e "\/issues\/4994"
grep -rI "from\ electrum " ../electrum-mona . 2> /dev/null | grep -v -e "\/locale\/" -e "README" -e "RELEASE-NOTES" -e "electrum\/{version\.ELECTRUM\_VERSION}" -e "\/issues\/4994"
grep -rI "from\ electrum\." ../electrum-mona . 2> /dev/null | grep -v -e "\/locale\/" -e "README" -e "RELEASE-NOTES" -e "electrum\/{version\.ELECTRUM\_VERSION}" -e "\/issues\/4994"
grep -rI "electrum\.gui" ../electrum-mona . 2> /dev/null | grep -v -e "\/locale\/" -e "README" -e "RELEASE-NOTES" -e "electrum\/{version\.ELECTRUM\_VERSION}" -e "\/issues\/4994"
pytest electrum_mona/tests/
