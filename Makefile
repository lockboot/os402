.PHONY: git-tag git-untag git-edit version test-mcp

# Extract version from Cargo.toml
VERSION := $(shell grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
TAG := v$(VERSION)

# Show current version
version:
	@echo "Current version: $(VERSION)"
	@echo "Tag: $(TAG)"

git-release: git-untag git-edit git-push-force git-tag 

git-push-force:
	git push -f

# Create and push a git tag based on Cargo.toml version
git-tag: version
	@echo "Creating tag $(TAG)..."
	@if git rev-parse "$(TAG)" >/dev/null 2>&1; then \
		echo "Error: Tag $(TAG) already exists"; \
		exit 1; \
	fi
	git tag -a "$(TAG)" -m "Release $(TAG)"
	git push origin "$(TAG)"
	@echo "Successfully created and pushed tag $(TAG)"

# Delete a git tag locally and from remote based on Cargo.toml version
git-untag: version
	@echo "Deleting tag $(TAG)..."
	@if ! git rev-parse "$(TAG)" >/dev/null 2>&1; then \
		echo "Warning: Tag $(TAG) does not exist locally"; \
	else \
		git tag -d "$(TAG)"; \
		echo "Deleted local tag $(TAG)"; \
	fi
	@if git ls-remote --tags origin | grep -q "refs/tags/$(TAG)"; then \
		git push origin ":refs/tags/$(TAG)"; \
		echo "Deleted remote tag $(TAG)"; \
	else \
		echo "Warning: Tag $(TAG) does not exist on remote"; \
	fi

# Amend the last commit to include currently staged files
git-edit:
	@echo "Amending last commit with staged changes..."
	@if [ -z "$$(git diff --cached --name-only)" ]; then \
		echo "Warning: No staged files to amend"; \
		echo "Current status:"; \
		git status --short; \
	else \
		echo "Staged files to be added to last commit:"; \
		git diff --cached --name-only; \
		git commit --amend --no-edit; \
		echo "Successfully amended last commit"; \
	fi

# Run MCP tests
test-mcp:
	$(MAKE) -C test/mcp
