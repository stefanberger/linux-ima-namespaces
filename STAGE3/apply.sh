#!/usr/bin/env bash

cd $(dirname "$0")

for f in *.patch; do
	echo "$f"
	git am < "${f}"
	if [ $? -ne 0 ]; then
		git am --abort
		num="$(sed -n "s/^From \([a-f0-9]\{40\}\).*/\1/p" "$f")"
		git cherry-pick "$num"
		if [ $? -ne 0 ]; then
			echo "Could not (cleanly) apply patch using git cherry-pick."
			echo "Please edit in another shell and once the patch is applied"
			echo "(using git cherry-pick --continue) press enter here."
			read enter
		fi
	fi
done
