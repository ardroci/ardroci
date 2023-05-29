SHELL:=/bin/bash
BASEDIR=$(pwd)
OUTPUTDIR=public

.PHONY: all
all: clean git_update build deploy

.PHONY: clean
clean:
	@echo "Removing public directory"
	rm -rf $(BASEDIR)/$(OUTPUTDIR)

.PHONY: git_update
git_update:
	@echo "Updating Hugo git repository"
	git pull
	# git submodule update --recursive

.PHONY: build
build:
	@echo "Generating static site content"
	hugo --gc 

# .PHONY: update_hugo_modules
# update_hugo:
# 	@echo "Update Hugo Modules"
# 	hugo mod tidy

# .PHONY: update_node_modules
# update_node_modules:
# 	@echo "Install node modules"
# 	hugo mod npm pack
# 	npm install

.PHONY: deploy
deploy:
	@echo "Preparing commit"
	git add -A
	git status 
	git commit -m "Deploying via Makefile" 
	git push -u origin $(git branch --show-current)

	@echo "Pushed to remote"