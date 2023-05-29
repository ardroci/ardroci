SHELL:=/bin/bash
BASEDIR=$(pwd)
OUTPUTDIR=public

.PHONY: all
all: clean git_update build deploy #publish

.PHONY: clean
clean:
	@echo "Removing public directory"
	rm -rf $(BASEDIR)/$(OUTPUTDIR)

.PHONY: git_update
git_update:
	@echo "Updating Hugo git repository"
	git pull

.PHONY: build
build:
	@echo "Generating static site content"
	hugo --gc --minify

.PHONY: deploy
deploy:
	@echo "Preparing commit"
	git add . 
	git status 
	git commit -m "Deploying via Makefile" 
	git push -u origin $(git branch --show-current)

	@echo "Pushed to remote"

# .PHONY: publish
# publish:
# 	@echo "Publishing to Cloudflare Workers"
# 	wrangler publish