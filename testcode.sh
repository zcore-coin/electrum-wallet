#!/bin/bash

if [ `grep -E -r "(import|from) electrum" ../electrum-mona | grep -v "electrum_mona" | grep -E -v -c "electrum-(locale|icons)"` -ge 1 ]; then
	echo "NG!!"
	grep -E -r "(import|from) electrum" ../electrum-mona | grep -v "electrum_mona" | grep -E -v "electrum-(locale|icons)"
	echo "NG!!"
else
	echo "OK!! electrum_ not found."
fi

pytest lib/tests/
