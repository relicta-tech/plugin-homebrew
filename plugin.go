// Package main implements the Homebrew formula publishing plugin for Relicta.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/relicta-tech/relicta-plugin-sdk/helpers"
	"github.com/relicta-tech/relicta-plugin-sdk/plugin"
)

// CommandExecutor executes shell commands. Used for testing.
type CommandExecutor interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	RunInDir(ctx context.Context, dir string, name string, args ...string) ([]byte, error)
}

// RealCommandExecutor executes real shell commands.
type RealCommandExecutor struct{}

// Run executes a command and returns combined output.
func (e *RealCommandExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

// RunInDir executes a command in a specific directory.
func (e *RealCommandExecutor) RunInDir(ctx context.Context, dir string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	return cmd.CombinedOutput()
}

// HomebrewPlugin implements the Homebrew formula publishing plugin.
type HomebrewPlugin struct {
	// cmdExecutor is used for executing shell commands. If nil, uses RealCommandExecutor.
	cmdExecutor CommandExecutor
}

// getExecutor returns the command executor, defaulting to RealCommandExecutor.
func (p *HomebrewPlugin) getExecutor() CommandExecutor {
	if p.cmdExecutor != nil {
		return p.cmdExecutor
	}
	return &RealCommandExecutor{}
}

// Config represents the Homebrew plugin configuration.
type Config struct {
	TapRepository       string
	FormulaName         string
	FormulaPath         string
	Description         string
	Homepage            string
	License             string
	DownloadURLTemplate string
	GitHubToken         string
	CommitMessage       string
	CreatePR            bool
	PRBranch            string
	Dependencies        []string
	InstallScript       string
	TestScript          string
}

// FormulaData contains data for formula template rendering.
type FormulaData struct {
	ClassName     string
	Description   string
	Homepage      string
	Version       string
	License       string
	URLX86_64     string
	SHA256X86_64  string
	URLArm64      string
	SHA256Arm64   string
	Dependencies  []string
	InstallScript string
	TestScript    string
}

// Default formula template.
const defaultFormulaTemplate = `class {{.ClassName}} < Formula
  desc "{{.Description}}"
  homepage "{{.Homepage}}"
  version "{{.Version}}"
  license "{{.License}}"

  on_macos do
    if Hardware::CPU.intel?
      url "{{.URLX86_64}}"
      sha256 "{{.SHA256X86_64}}"
    elsif Hardware::CPU.arm?
      url "{{.URLArm64}}"
      sha256 "{{.SHA256Arm64}}"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "{{.URLX86_64}}"
      sha256 "{{.SHA256X86_64}}"
    elsif Hardware::CPU.arm?
      url "{{.URLArm64}}"
      sha256 "{{.SHA256Arm64}}"
    end
  end
{{range .Dependencies}}
  depends_on "{{.}}"
{{end}}
  def install
    {{.InstallScript}}
  end

  test do
    {{.TestScript}}
  end
end
`

// GetInfo returns plugin metadata.
func (p *HomebrewPlugin) GetInfo() plugin.Info {
	return plugin.Info{
		Name:        "homebrew",
		Version:     "2.0.0",
		Description: "Publish Homebrew formula for releases",
		Author:      "Relicta Team",
		Hooks: []plugin.Hook{
			plugin.HookPostPublish,
		},
		ConfigSchema: `{
			"type": "object",
			"properties": {
				"tap_repository": {"type": "string", "description": "Homebrew tap repository (e.g., user/homebrew-tap)"},
				"formula_name": {"type": "string", "description": "Formula name (defaults to project name)"},
				"formula_path": {"type": "string", "description": "Path to formula in tap repo"},
				"description": {"type": "string", "description": "Formula description"},
				"homepage": {"type": "string", "description": "Project homepage URL"},
				"license": {"type": "string", "description": "Project license", "default": "MIT"},
				"download_url_template": {"type": "string", "description": "URL template for downloads"},
				"github_token": {"type": "string", "description": "GitHub token (or use HOMEBREW_GITHUB_TOKEN env)"},
				"commit_message": {"type": "string", "description": "Commit message template"},
				"create_pr": {"type": "boolean", "description": "Create PR instead of direct push", "default": false},
				"pr_branch": {"type": "string", "description": "PR branch name template"},
				"dependencies": {"type": "array", "items": {"type": "string"}, "description": "Homebrew dependencies"},
				"install_script": {"type": "string", "description": "Custom install script (Ruby)"},
				"test_script": {"type": "string", "description": "Custom test script (Ruby)"}
			},
			"required": ["tap_repository", "download_url_template"]
		}`,
	}
}

// Execute runs the plugin for a given hook.
func (p *HomebrewPlugin) Execute(ctx context.Context, req plugin.ExecuteRequest) (*plugin.ExecuteResponse, error) {
	cfg := p.parseConfig(req.Config)

	switch req.Hook {
	case plugin.HookPostPublish:
		return p.publishFormula(ctx, cfg, req.Context, req.DryRun)
	default:
		return &plugin.ExecuteResponse{
			Success: true,
			Message: fmt.Sprintf("Hook %s not handled", req.Hook),
		}, nil
	}
}

// publishFormula generates and publishes a Homebrew formula.
func (p *HomebrewPlugin) publishFormula(ctx context.Context, cfg *Config, releaseCtx plugin.ReleaseContext, dryRun bool) (*plugin.ExecuteResponse, error) {
	formulaName := cfg.FormulaName
	if formulaName == "" {
		formulaName = releaseCtx.RepositoryName
	}

	version := strings.TrimPrefix(releaseCtx.Version, "v")
	tag := releaseCtx.TagName

	urlX86_64 := p.resolveURL(cfg.DownloadURLTemplate, version, tag, "darwin", "amd64")
	urlArm64 := p.resolveURL(cfg.DownloadURLTemplate, version, tag, "darwin", "arm64")

	if dryRun {
		return &plugin.ExecuteResponse{
			Success: true,
			Message: "Would publish Homebrew formula",
			Outputs: map[string]any{
				"tap_repository": cfg.TapRepository,
				"formula_name":   formulaName,
				"version":        version,
				"url_x86_64":     urlX86_64,
				"url_arm64":      urlArm64,
			},
		}, nil
	}

	sha256X86_64, err := p.fetchSHA256(ctx, urlX86_64)
	if err != nil {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to fetch x86_64 binary checksum: %v", err),
		}, nil
	}

	sha256Arm64, err := p.fetchSHA256(ctx, urlArm64)
	if err != nil {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to fetch arm64 binary checksum: %v", err),
		}, nil
	}

	formulaContent, err := p.generateFormula(cfg, formulaName, version, urlX86_64, sha256X86_64, urlArm64, sha256Arm64)
	if err != nil {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to generate formula: %v", err),
		}, nil
	}

	if err := p.updateTap(ctx, cfg, formulaName, version, formulaContent); err != nil {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to update tap: %v", err),
		}, nil
	}

	return &plugin.ExecuteResponse{
		Success: true,
		Message: fmt.Sprintf("Published Homebrew formula %s v%s", formulaName, version),
		Outputs: map[string]any{
			"formula_name": formulaName,
			"version":      version,
			"tap":          cfg.TapRepository,
		},
	}, nil
}

func (p *HomebrewPlugin) resolveURL(urlTemplate, version, tag, goos, arch string) string {
	url := urlTemplate
	url = strings.ReplaceAll(url, "{{version}}", version)
	url = strings.ReplaceAll(url, "{{tag}}", tag)
	url = strings.ReplaceAll(url, "{{os}}", goos)
	url = strings.ReplaceAll(url, "{{arch}}", arch)
	return url
}

func (p *HomebrewPlugin) fetchSHA256(ctx context.Context, url string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Minute}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, resp.Body); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func (p *HomebrewPlugin) generateFormula(cfg *Config, name, version, urlX86_64, sha256X86_64, urlArm64, sha256Arm64 string) (string, error) {
	className := p.toClassName(name)

	installScript := cfg.InstallScript
	if installScript == "" {
		installScript = fmt.Sprintf(`bin.install "%s"`, name)
	}

	testScript := cfg.TestScript
	if testScript == "" {
		testScript = fmt.Sprintf(`system "#{bin}/%s", "--version"`, name)
	}

	data := FormulaData{
		ClassName:     className,
		Description:   cfg.Description,
		Homepage:      cfg.Homepage,
		Version:       version,
		License:       cfg.License,
		URLX86_64:     urlX86_64,
		SHA256X86_64:  sha256X86_64,
		URLArm64:      urlArm64,
		SHA256Arm64:   sha256Arm64,
		Dependencies:  cfg.Dependencies,
		InstallScript: installScript,
		TestScript:    testScript,
	}

	tmpl, err := template.New("formula").Parse(defaultFormulaTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (p *HomebrewPlugin) toClassName(name string) string {
	parts := strings.Split(name, "-")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, "")
}

func (p *HomebrewPlugin) updateTap(ctx context.Context, cfg *Config, formulaName, version, formulaContent string) error {
	executor := p.getExecutor()

	tmpDir, err := os.MkdirTemp("", "homebrew-tap-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	repoURL := fmt.Sprintf("https://%s@github.com/%s.git", cfg.GitHubToken, cfg.TapRepository)
	if out, err := executor.Run(ctx, "git", "clone", "--depth=1", repoURL, tmpDir); err != nil {
		return fmt.Errorf("git clone failed: %s", string(out))
	}

	formulaPath := cfg.FormulaPath
	if formulaPath == "" {
		formulaPath = fmt.Sprintf("Formula/%s.rb", formulaName)
	}
	fullPath := filepath.Join(tmpDir, formulaPath)

	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(fullPath, []byte(formulaContent), 0644); err != nil {
		return err
	}

	if out, err := executor.RunInDir(ctx, tmpDir, "git", "add", formulaPath); err != nil {
		return fmt.Errorf("git add failed: %s", string(out))
	}

	commitMsg := cfg.CommitMessage
	if commitMsg == "" {
		commitMsg = fmt.Sprintf("%s {{version}}", formulaName)
	}
	commitMsg = strings.ReplaceAll(commitMsg, "{{version}}", version)

	if out, err := executor.RunInDir(ctx, tmpDir, "git", "commit", "-m", commitMsg); err != nil {
		return fmt.Errorf("git commit failed: %s", string(out))
	}

	if cfg.CreatePR {
		branchName := cfg.PRBranch
		if branchName == "" {
			branchName = fmt.Sprintf("update-%s-{{version}}", formulaName)
		}
		branchName = strings.ReplaceAll(branchName, "{{version}}", version)

		if out, err := executor.RunInDir(ctx, tmpDir, "git", "checkout", "-b", branchName); err != nil {
			return fmt.Errorf("git checkout failed: %s", string(out))
		}

		if out, err := executor.RunInDir(ctx, tmpDir, "git", "push", "-u", "origin", branchName); err != nil {
			return fmt.Errorf("git push failed: %s", string(out))
		}

		// gh pr create - ignore errors as this is optional
		_, _ = executor.RunInDir(ctx, tmpDir, "gh", "pr", "create",
			"--repo", cfg.TapRepository,
			"--title", fmt.Sprintf("Update %s to %s", formulaName, version),
			"--body", fmt.Sprintf("Automated formula update for %s version %s", formulaName, version),
			"--head", branchName)
	} else {
		if out, err := executor.RunInDir(ctx, tmpDir, "git", "push"); err != nil {
			return fmt.Errorf("git push failed: %s", string(out))
		}
	}

	return nil
}

func (p *HomebrewPlugin) parseConfig(raw map[string]any) *Config {
	parser := helpers.NewConfigParser(raw)

	// Get GitHub token - check multiple env vars manually
	token := parser.GetString("github_token", "HOMEBREW_GITHUB_TOKEN", "")
	if token == "" {
		if envToken := os.Getenv("GITHUB_TOKEN"); envToken != "" {
			token = envToken
		}
	}

	return &Config{
		TapRepository:       parser.GetString("tap_repository", "", ""),
		FormulaName:         parser.GetString("formula_name", "", ""),
		FormulaPath:         parser.GetString("formula_path", "", ""),
		Description:         parser.GetString("description", "", ""),
		Homepage:            parser.GetString("homepage", "", ""),
		License:             parser.GetString("license", "", "MIT"),
		DownloadURLTemplate: parser.GetString("download_url_template", "", ""),
		GitHubToken:         token,
		CommitMessage:       parser.GetString("commit_message", "", ""),
		CreatePR:            parser.GetBool("create_pr", false),
		PRBranch:            parser.GetString("pr_branch", "", ""),
		Dependencies:        parser.GetStringSlice("dependencies", nil),
		InstallScript:       parser.GetString("install_script", "", ""),
		TestScript:          parser.GetString("test_script", "", ""),
	}
}

// Validate validates the plugin configuration.
func (p *HomebrewPlugin) Validate(_ context.Context, config map[string]any) (*plugin.ValidateResponse, error) {
	vb := helpers.NewValidationBuilder()
	parser := helpers.NewConfigParser(config)

	tapRepo := parser.GetString("tap_repository", "", "")
	if tapRepo == "" {
		vb.AddError("tap_repository", "Homebrew tap repository is required")
	} else if !strings.Contains(tapRepo, "/") {
		vb.AddError("tap_repository", "must be in format 'owner/repo'")
	}

	downloadURL := parser.GetString("download_url_template", "", "")
	if downloadURL == "" {
		vb.AddError("download_url_template", "Download URL template is required")
	}

	// Token warning is optional - validation will succeed without token
	// but push will fail at runtime if not set

	return vb.Build(), nil
}
