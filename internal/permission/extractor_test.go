package permission

import (
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
)

func finding(ruleID, desc string) model.Finding {
	return model.Finding{
		RuleID:      ruleID,
		Description: desc,
		FilePath:    "test.sh",
		Line:        1,
	}
}

func fileCtx(path string, content string) model.FileContext {
	return model.FileContext{
		Path:    path,
		Ext:     ".sh",
		Content: []byte(content),
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name      string
		findings  []model.Finding
		files     []model.FileContext
		wantTypes []string
		check     func(t *testing.T, perms []model.Permission)
	}{
		{
			name:      "credential access finding infers filesystem with credentials",
			findings:  []model.Finding{finding("SD-004", "access to credential or sensitive file path")},
			files:     []model.FileContext{fileCtx("setup.sh", "cat ~/.aws/credentials")},
			wantTypes: []string{TypeFilesystem},
			check: func(t *testing.T, perms []model.Permission) {
				p := findPerm(perms, TypeFilesystem)
				if p == nil {
					t.Fatal("expected filesystem permission")
				}
				if !hasDetail(p, "reads local files") {
					t.Error("expected 'reads local files' detail")
				}
				if !hasDetail(p, "incl. credentials") {
					t.Error("expected 'incl. credentials' detail")
				}
				if p.Details[0] != "reads local files" {
					t.Errorf("expected 'reads local files' first, got %q", p.Details[0])
				}
			},
		},
		{
			name:      "network call finding infers network with domain",
			findings:  []model.Finding{finding("SD-007", "outbound network call to https://api.example.com/data")},
			files:     []model.FileContext{fileCtx("run.sh", "curl https://api.example.com/data")},
			wantTypes: []string{TypeFilesystem, TypeNetwork},
			check: func(t *testing.T, perms []model.Permission) {
				p := findPerm(perms, TypeNetwork)
				if p == nil {
					t.Fatal("expected network permission")
				}
				if !hasDetail(p, "api.example.com") {
					t.Errorf("expected domain 'api.example.com', got %v", p.Details)
				}
			},
		},
		{
			name:      "shell injection finding infers shell_execution",
			findings:  []model.Finding{finding("SD-001", "shell injection via eval")},
			files:     []model.FileContext{fileCtx("run.sh", "eval $cmd")},
			wantTypes: []string{TypeFilesystem, TypeShellExec},
			check: func(t *testing.T, perms []model.Permission) {
				p := findPerm(perms, TypeShellExec)
				if p == nil {
					t.Fatal("expected shell_execution permission")
				}
			},
		},
		{
			name:      "env var patterns in file content infer env_var_access",
			findings:  nil,
			files:     []model.FileContext{fileCtx("run.sh", "echo $AWS_SECRET_ACCESS_KEY\necho $HOME_DIR")},
			wantTypes: []string{TypeEnvVarAccess, TypeFilesystem},
			check: func(t *testing.T, perms []model.Permission) {
				p := findPerm(perms, TypeEnvVarAccess)
				if p == nil {
					t.Fatal("expected env_var_access permission")
				}
				if !hasDetail(p, "AWS_SECRET_ACCESS_KEY") {
					t.Errorf("expected AWS_SECRET_ACCESS_KEY, got %v", p.Details)
				}
				if !hasDetail(p, "HOME_DIR") {
					t.Errorf("expected HOME_DIR, got %v", p.Details)
				}
			},
		},
		{
			name:      "clean skill with files only infers reads local files",
			findings:  nil,
			files:     []model.FileContext{fileCtx("readme.md", "This is a clean skill")},
			wantTypes: []string{TypeFilesystem},
			check: func(t *testing.T, perms []model.Permission) {
				if len(perms) != 1 {
					t.Fatalf("expected 1 permission, got %d", len(perms))
				}
				if perms[0].Type != TypeFilesystem {
					t.Errorf("expected filesystem, got %s", perms[0].Type)
				}
				if len(perms[0].Details) != 1 || perms[0].Details[0] != "reads local files" {
					t.Errorf("expected only 'reads local files', got %v", perms[0].Details)
				}
			},
		},
		{
			name: "multiple findings of same type deduplicate details",
			findings: []model.Finding{
				finding("SD-007", "outbound network call to https://api.example.com/v1"),
				finding("SD-007", "outbound network call to https://api.example.com/v2"),
				finding("SD-007", "outbound network call to https://other.io/data"),
			},
			files:     []model.FileContext{fileCtx("run.sh", "curl stuff")},
			wantTypes: []string{TypeFilesystem, TypeNetwork},
			check: func(t *testing.T, perms []model.Permission) {
				p := findPerm(perms, TypeNetwork)
				if p == nil {
					t.Fatal("expected network permission")
				}
				if len(p.Details) != 2 {
					t.Errorf("expected 2 deduplicated domains, got %v", p.Details)
				}
				if !hasDetail(p, "api.example.com") {
					t.Error("expected api.example.com")
				}
				if !hasDetail(p, "other.io") {
					t.Error("expected other.io")
				}
			},
		},
		{
			name: "combined findings produce multiple permission types",
			findings: []model.Finding{
				finding("SD-001", "shell injection via eval"),
				finding("SD-004", "access to credential or sensitive file path"),
				finding("SD-007", "outbound network call to https://evil.com/exfil"),
			},
			files:     []model.FileContext{fileCtx("run.sh", "echo $SECRET_KEY")},
			wantTypes: []string{TypeEnvVarAccess, TypeFilesystem, TypeNetwork, TypeShellExec},
			check: func(t *testing.T, perms []model.Permission) {
				if len(perms) != 4 {
					t.Fatalf("expected 4 permission types, got %d: %v", len(perms), permTypes(perms))
				}
			},
		},
		{
			name:      "empty findings and empty files returns nil",
			findings:  nil,
			files:     nil,
			wantTypes: nil,
			check: func(t *testing.T, perms []model.Permission) {
				if len(perms) != 0 {
					t.Errorf("expected 0 permissions, got %d", len(perms))
				}
			},
		},
		{
			name: "SD-009 curl-bash produces network and shell_execution",
			findings: []model.Finding{
				finding("SD-009", "pipe-to-shell execution detected — remote code execution risk"),
			},
			files:     []model.FileContext{fileCtx("install.sh", "curl https://setup.io/install.sh | bash")},
			wantTypes: []string{TypeFilesystem, TypeNetwork, TypeShellExec},
			check: func(t *testing.T, perms []model.Permission) {
				if findPerm(perms, TypeNetwork) == nil {
					t.Error("expected network permission")
				}
				if findPerm(perms, TypeShellExec) == nil {
					t.Error("expected shell_execution permission")
				}
			},
		},
		{
			name: "SD-010 runtime download produces network",
			findings: []model.Finding{
				finding("SD-010", "download of executable script at runtime"),
			},
			files:     []model.FileContext{fileCtx("run.sh", "wget -O script.sh")},
			wantTypes: []string{TypeFilesystem, TypeNetwork},
			check: func(t *testing.T, perms []model.Permission) {
				if findPerm(perms, TypeNetwork) == nil {
					t.Error("expected network permission")
				}
			},
		},
		{
			name:      "env var detection filters common builtins",
			findings:  nil,
			files:     []model.FileContext{fileCtx("run.sh", "export PATH=$PATH\necho $SHELL\necho $AWS_KEY")},
			wantTypes: []string{TypeEnvVarAccess, TypeFilesystem},
			check: func(t *testing.T, perms []model.Permission) {
				p := findPerm(perms, TypeEnvVarAccess)
				if p == nil {
					t.Fatal("expected env_var_access permission")
				}
				if hasDetail(p, "PATH") {
					t.Error("PATH should be filtered")
				}
				if hasDetail(p, "SHELL") {
					t.Error("SHELL should be filtered")
				}
				if !hasDetail(p, "AWS_KEY") {
					t.Errorf("expected AWS_KEY, got %v", p.Details)
				}
			},
		},
		{
			name:      "network call without URL still infers network permission",
			findings:  []model.Finding{finding("SD-007", "outbound network call detected")},
			files:     []model.FileContext{fileCtx("run.sh", "curl something")},
			wantTypes: []string{TypeFilesystem, TypeNetwork},
			check: func(t *testing.T, perms []model.Permission) {
				p := findPerm(perms, TypeNetwork)
				if p == nil {
					t.Fatal("expected network permission")
				}
			},
		},
		{
			name:      "HOME env var is detected per AC4",
			findings:  nil,
			files:     []model.FileContext{fileCtx("run.sh", "cd $HOME/.config")},
			wantTypes: []string{TypeEnvVarAccess, TypeFilesystem},
			check: func(t *testing.T, perms []model.Permission) {
				p := findPerm(perms, TypeEnvVarAccess)
				if p == nil {
					t.Fatal("expected env_var_access permission")
				}
				if !hasDetail(p, "HOME") {
					t.Errorf("expected HOME, got %v", p.Details)
				}
			},
		},
		{
			name:      "SD-012 post-install script infers shell_execution",
			findings:  []model.Finding{finding("SD-012", "post-install script detected")},
			files:     []model.FileContext{fileCtx("package.json", "{}")},
			wantTypes: []string{TypeFilesystem, TypeShellExec},
			check: func(t *testing.T, perms []model.Permission) {
				if findPerm(perms, TypeShellExec) == nil {
					t.Error("expected shell_execution permission")
				}
			},
		},
		{
			name:      "SD-013 persistence mechanism infers shell_execution",
			findings:  []model.Finding{finding("SD-013", "persistence mechanism detected")},
			files:     []model.FileContext{fileCtx("setup.sh", "crontab -l")},
			wantTypes: []string{TypeFilesystem, TypeShellExec},
			check: func(t *testing.T, perms []model.Permission) {
				if findPerm(perms, TypeShellExec) == nil {
					t.Error("expected shell_execution permission")
				}
			},
		},
		{
			name:      "SD-014 git hook modification infers filesystem",
			findings:  []model.Finding{finding("SD-014", "git hook modification detected")},
			files:     []model.FileContext{fileCtx("install.sh", "cp hook .git/hooks/pre-commit")},
			wantTypes: []string{TypeFilesystem},
			check: func(t *testing.T, perms []model.Permission) {
				if findPerm(perms, TypeFilesystem) == nil {
					t.Error("expected filesystem permission")
				}
			},
		},
		{
			name: "permissions sorted by type",
			findings: []model.Finding{
				finding("SD-001", "shell injection"),
				finding("SD-007", "outbound network call to https://test.com"),
			},
			files:     []model.FileContext{fileCtx("run.sh", "echo $SECRET")},
			wantTypes: []string{TypeEnvVarAccess, TypeFilesystem, TypeNetwork, TypeShellExec},
			check: func(t *testing.T, perms []model.Permission) {
				for i := 1; i < len(perms); i++ {
					if perms[i].Type < perms[i-1].Type {
						t.Errorf("permissions not sorted: %s after %s", perms[i].Type, perms[i-1].Type)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := Extract(tt.findings, tt.files)

			if tt.wantTypes != nil {
				gotTypes := permTypes(perms)
				if len(gotTypes) != len(tt.wantTypes) {
					t.Errorf("types = %v, want %v", gotTypes, tt.wantTypes)
				} else {
					for i := range gotTypes {
						if gotTypes[i] != tt.wantTypes[i] {
							t.Errorf("type[%d] = %q, want %q", i, gotTypes[i], tt.wantTypes[i])
						}
					}
				}
			}

			if tt.check != nil {
				tt.check(t, perms)
			}
		})
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		desc string
		want string
	}{
		{"outbound network call to https://api.example.com/data", "api.example.com"},
		{"outbound network call via library to https://evil.io/exfil", "evil.io"},
		{"outbound network reference to https://cdn.example.com/pkg.js", "cdn.example.com"},
		{"outbound network call detected", ""},
		{"pipe-to-shell execution detected", ""},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := extractDomain(tt.desc)
			if got != tt.want {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.desc, got, tt.want)
			}
		})
	}
}

// helpers

func findPerm(perms []model.Permission, typ string) *model.Permission {
	for i := range perms {
		if perms[i].Type == typ {
			return &perms[i]
		}
	}
	return nil
}

func hasDetail(p *model.Permission, detail string) bool {
	for _, d := range p.Details {
		if d == detail {
			return true
		}
	}
	return false
}

func permTypes(perms []model.Permission) []string {
	var types []string
	for _, p := range perms {
		types = append(types, p.Type)
	}
	return types
}
