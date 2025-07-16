package user

import (
	"fmt"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
)

type Manager struct {
	homeDirBase string
	shell       string
}

type User struct {
	Username string
	UID      int
	GID      int
	HomeDir  string
	Shell    string
}

func NewManager(homeDirBase, shell string) *Manager {
	return &Manager{
		homeDirBase: homeDirBase,
		shell:       shell,
	}
}

func (m *Manager) GetUser(username string) (*User, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup user %s: %w", username, err)
	}

	uid := 0
	gid := 0
	fmt.Sscanf(u.Uid, "%d", &uid)
	fmt.Sscanf(u.Gid, "%d", &gid)

	return &User{
		Username: u.Username,
		UID:      uid,
		GID:      gid,
		HomeDir:  u.HomeDir,
		Shell:    "/bin/bash", // Default shell since os/user.User doesn't have Shell field
	}, nil
}

func (m *Manager) CreateUser(username, email string) (*User, error) {
	// Check if user already exists
	if _, err := user.Lookup(username); err == nil {
		return m.GetUser(username)
	}

	// Create user with useradd command using sudo
	cmd := exec.Command("sudo", "useradd",
		"-m",           // Create home directory
		"-s", m.shell,  // Set shell
		"-c", fmt.Sprintf("OIDC User (%s)", email), // Comment/GECOS
		username,
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to create user %s: %w (output: %s)", username, err, string(output))
	}

	// Get the newly created user
	return m.GetUser(username)
}

func (m *Manager) EnsureUserDirectory(username string) error {
	// useradd -m already creates the home directory with correct ownership
	// This function is now a no-op since the directory is handled by useradd
	return nil
}

// SetupUserEnvironment is deprecated - useradd -m handles all necessary setup
// This method has been removed as useradd -m creates home directory with correct ownership

func (m *Manager) GetUserCredentials(username string) (*syscall.Credential, error) {
	user, err := m.GetUser(username)
	if err != nil {
		return nil, err
	}

	return &syscall.Credential{
		Uid: uint32(user.UID),
		Gid: uint32(user.GID),
	}, nil
}

func (m *Manager) ValidateUsername(username string) error {
	// Check for invalid characters
	if strings.ContainsAny(username, ":/\\?%*|\"") {
		return fmt.Errorf("username contains invalid characters")
	}

	// Check length
	if len(username) < 1 || len(username) > 32 {
		return fmt.Errorf("username must be between 1 and 32 characters")
	}

	// Check if it starts with a number
	if len(username) > 0 && username[0] >= '0' && username[0] <= '9' {
		return fmt.Errorf("username cannot start with a number")
	}

	return nil
}

func (m *Manager) SanitizeUsername(email string) string {
	// Extract username from email
	username := strings.Split(email, "@")[0]
	
	// Replace invalid characters with underscores
	username = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, username)
	
	// Ensure it doesn't start with a number
	if len(username) > 0 && username[0] >= '0' && username[0] <= '9' {
		username = "u" + username
	}
	
	// Truncate if too long
	if len(username) > 32 {
		username = username[:32]
	}
	
	return strings.ToLower(username)
}