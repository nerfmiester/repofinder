goinstall:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build
zipdir:	goinstall
	zip -9 -r -x *.git* --exclude=*.DS_Store* --exclude=*.idea* repofinder.zip *
gitAdd: zipdir
	git add -f -v *
gitCommit: gitAdd
	git commit -m "$(commit_message)"
gitPush: gitCommit
	git push
mvfile:	gitPush
	mv repofinder.zip /Users/adrianjackson/Dropbox/Public