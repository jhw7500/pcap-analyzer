# GitHub Actions Configuration

This directory contains GitHub Actions workflows for automated testing, code review, and quality assurance using Claude Code and Gemini.

## Workflows

### Tests

#### `test.yml` - Lint & Test
Runs on every push to `main` and on pull requests.

- **lint**: ruff static analysis
- **test**: pytest with coverage (e2e / slow / tshark markers excluded in CI)

### Claude Code Workflows

#### `claude.yml` - Interactive Claude Code Assistant
Triggers when `@claude` is mentioned in issues, PR comments, or reviews.

**Required Secret:** `CLAUDE_CODE_OAUTH_TOKEN`

#### `claude-code-review.yml` - Automatic PR Review
Automatically reviews pull requests when opened or updated.

**Required Secret:** `CLAUDE_CODE_OAUTH_TOKEN`

### Gemini Workflows

#### `gemini-auto-review.yml` - Automatic PR Review
Automatically reviews pull requests when opened or updated.

**Required Secret:** `GEMINI_API_KEY`

#### `gemini-dispatch.yml` - Gemini Request Dispatcher
Central dispatcher for routing Gemini-related requests (requires `@gemini-cli` mention).

#### `gemini-invoke.yml` - Direct Gemini Invocation
Handles direct Gemini CLI invocations for code analysis.

#### `gemini-review.yml` - Gemini PR Review (workflow_call)
Called by dispatch/pr-review workflows.

#### `gemini-pr-review.yml` - Manual Gemini PR Review
Manual workflow_dispatch trigger for ad-hoc PR reviews.

#### `gemini-triage.yml` - Issue Triage (workflow_call)
Called by dispatch/issue-triage workflows.

#### `gemini-issue-triage.yml` - Manual Issue Triage
Manual workflow_dispatch trigger for ad-hoc issue triage.

#### `gemini-scheduled-triage.yml` - Scheduled Issue Analysis
Manual workflow_dispatch trigger (auto schedule disabled).

### Automation

#### `bump-automation-ref.yml` - Bump Shared Workflow Refs
Triggered when `automation_ref` in `workflow-config.yml` changes. Creates a PR that rewrites all `jhw7500/automation@*` refs to the new version.

## Setup

### 1. Claude Code Setup

1. Go to https://claude.com/code/oauth and generate an OAuth token
2. Add as repository secret: **`CLAUDE_CODE_OAUTH_TOKEN`**

### 2. Gemini Setup

1. Get an API key from https://aistudio.google.com/app/apikey
2. Add as repository secret: **`GEMINI_API_KEY`**

## Version Management

The `automation_ref` field in `workflow-config.yml` pins the shared workflow version.
Update it there and `bump-automation-ref.yml` will auto-create a PR to rewrite all refs.
