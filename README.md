# Homebrew Plugin for Relicta

Official Homebrew plugin for [Relicta](https://github.com/relicta-tech/relicta) - Publish Homebrew formulas for your releases.

## Installation

```bash
relicta plugin install homebrew
relicta plugin enable homebrew
```

## Configuration

Add to your `release.config.yaml`:

```yaml
plugins:
  - name: homebrew
    enabled: true
    config:
      tap_repository: "your-org/homebrew-tap"
      download_url_template: "https://github.com/your-org/your-repo/releases/download/{{tag}}/your-app_{{os}}_{{arch}}.tar.gz"
      description: "Your app description"
      homepage: "https://your-homepage.com"
      license: "MIT"
```

## Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `tap_repository` | string | Yes | Homebrew tap repository (e.g., `user/homebrew-tap`) |
| `download_url_template` | string | Yes | URL template for downloads. Supports `{{version}}`, `{{tag}}`, `{{os}}`, `{{arch}}` |
| `formula_name` | string | No | Formula name (defaults to project name) |
| `formula_path` | string | No | Path to formula in tap repo (default: `Formula/<name>.rb`) |
| `description` | string | No | Formula description |
| `homepage` | string | No | Project homepage URL |
| `license` | string | No | Project license (default: `MIT`) |
| `github_token` | string | No | GitHub token (or use `HOMEBREW_GITHUB_TOKEN` / `GITHUB_TOKEN` env) |
| `commit_message` | string | No | Commit message template (supports `{{version}}`) |
| `create_pr` | boolean | No | Create PR instead of direct push (default: `false`) |
| `pr_branch` | string | No | PR branch name template (supports `{{version}}`) |
| `dependencies` | array | No | List of Homebrew dependencies |
| `install_script` | string | No | Custom Ruby install script |
| `test_script` | string | No | Custom Ruby test script |

## Environment Variables

- `HOMEBREW_GITHUB_TOKEN` - GitHub token for pushing to tap
- `GITHUB_TOKEN` - Fallback GitHub token

## Hooks

- `post_publish` - Updates Homebrew formula after release is published

## License

MIT License - see [LICENSE](LICENSE) for details.
