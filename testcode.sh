#!/bin/bash

if [ `grep -E -r "(import|from) electrum" ../electrum-mona | grep -v -c "electrum_mona"` -ge 1 ]; then
	echo "NG!!"
	grep -E -r "(import|from) electrum" ../electrum-mona | grep -v "electrum_mona"
	echo "NG!!"
else
	echo "OK!! electrum_ not found."
fi

pytest lib/tests/
