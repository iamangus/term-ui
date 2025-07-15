package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/creack/pty"
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/google/uuid"

	"terminal/internal/auth"
	"terminal/internal/config"
	"terminal/internal/session"
	"terminal/internal/user"
)

var debugMode bool

type TerminalSession struct {
	ID          string
	ptmx        *os.File
	cmd         *exec.Cmd
	mutex       sync.Mutex
	active      bool
	connections map[*websocket.Conn]bool
	connMutex   sync.Mutex
	buffer      []byte
	bufferMutex sync.Mutex
	createdAt   time.Time
	lastUsed    time.Time
	username    string
}

type SessionManager struct {
	sessions map[string]*TerminalSession
	mutex    sync.RWMutex
}

var (
	terminalSessionManager *SessionManager
	appConfig              *config.Config
	authHandlers           *auth.Handlers
	sessionManager         *session.Manager
	userManager            *user.Manager
)

func initTerminalSessionManager() {
	terminalSessionManager = &SessionManager{
		sessions: make(map[string]*TerminalSession),
	}
}

func (sm *SessionManager) GetOrCreateSession(sessionID, username string) (*TerminalSession, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// Check if session already exists in memory
	if session, exists := sm.sessions[sessionID]; exists {
		session.lastUsed = time.Now()
		return session, nil
	}
	
	// Create new session
	session, err := sm.createTerminalSession(sessionID, username)
	if err != nil {
		return nil, err
	}
	
	sm.sessions[sessionID] = session
	return session, nil
}

func (sm *SessionManager) createTerminalSession(sessionID, username string) (*TerminalSession, error) {
	// Get user credentials
	user, err := userManager.GetUser(username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user %s: %v", username, err)
	}

	// Get user shell
	shell := appConfig.User.Shell
	if shell == "" {
		shell = "/bin/bash"
	}

	// Get user credentials for process execution
	creds, err := userManager.GetUserCredentials(username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credentials: %v", err)
	}

	// Start the shell command as the user
	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"COLUMNS=80",
		"LINES=24",
		"HOME="+user.HomeDir,
		"USER="+user.Username,
		"LOGNAME="+user.Username,
		"SHELL="+shell,
	)
	cmd.Dir = user.HomeDir

	// Set the user credentials
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: creds,
	}

	// Start with a pty
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to start pty: %v", err)
	}

	// Set initial size
	err = pty.Setsize(ptmx, &pty.Winsize{
		Rows: 24,
		Cols: 80,
	})
	if err != nil {
		log.Printf("Warning: failed to set initial pty size: %v", err)
	}

	session := &TerminalSession{
		ID:          sessionID,
		ptmx:        ptmx,
		cmd:         cmd,
		active:      true,
		connections: make(map[*websocket.Conn]bool),
		createdAt:   time.Now(),
		lastUsed:    time.Now(),
		username:    username,
	}

	return session, nil
}

func (t *TerminalSession) AddConnection(conn *websocket.Conn) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	
	t.connections[conn] = true
	
	// Send existing buffer to new connection
	t.bufferMutex.Lock()
	if len(t.buffer) > 0 {
		conn.WriteMessage(websocket.TextMessage, t.buffer)
	}
	t.bufferMutex.Unlock()
}

func (t *TerminalSession) RemoveConnection(conn *websocket.Conn) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	
	delete(t.connections, conn)
}

func (t *TerminalSession) BroadcastToConnections(messageType int, data []byte) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	
	// Add to buffer
	t.bufferMutex.Lock()
	// Keep buffer size reasonable (last 100KB)
	if len(t.buffer)+len(data) > 100*1024 {
		// Remove first half of buffer
		halfSize := len(t.buffer) / 2
		t.buffer = t.buffer[halfSize:]
	}
	t.buffer = append(t.buffer, data...)
	t.bufferMutex.Unlock()
	
	// Broadcast to all connections
	for conn := range t.connections {
		if err := conn.WriteMessage(messageType, data); err != nil {
			// Remove failed connection
			delete(t.connections, conn)
		}
	}
}

func (t *TerminalSession) writeInput(data []byte) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	
	if !t.active {
		return fmt.Errorf("terminal session not active")
	}
	
	_, err := t.ptmx.Write(data)
	return err
}

func (t *TerminalSession) resize(cols, rows int) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	
	if !t.active {
		return fmt.Errorf("terminal session not active")
	}
	
	return pty.Setsize(t.ptmx, &pty.Winsize{
		Rows: uint16(rows),
		Cols: uint16(cols),
	})
}

func (t *TerminalSession) close() {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	
	if t.active {
		t.active = false
		if t.ptmx != nil {
			t.ptmx.Close()
		}
		if t.cmd != nil && t.cmd.Process != nil {
			t.cmd.Process.Kill()
		}
	}
}

func handleWebSocket(c *websocket.Conn) {
	defer c.Close()
	
	// Get username from authenticated context
	username := c.Locals("username").(string)
	if username == "" {
		log.Printf("WebSocket connection without username")
		return
	}
	
	// Get or create session ID from query parameter
	sessionID := c.Query("session")
	if sessionID == "" {
		sessionID = uuid.New().String()
		log.Printf("Generated new session ID: %s for user: %s", sessionID, username)
	}
	
	// Get or create terminal session
	session, err := terminalSessionManager.GetOrCreateSession(sessionID, username)
	if err != nil {
		log.Printf("Failed to get/create session: %v", err)
		return
	}
	
	// Add this connection to the session
	session.AddConnection(c)
	defer session.RemoveConnection(c)
	
	if debugMode {
		log.Printf("WebSocket connected to session %s for user %s", sessionID, username)
	}

	// Use a context for clean cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Start terminal output reader if this is the first connection
	session.connMutex.Lock()
	isFirstConnection := len(session.connections) == 1
	session.connMutex.Unlock()
	
	if isFirstConnection {
		// Copy terminal output to all connections
		go func() {
			defer cancel()
			
			buf := make([]byte, 4096)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				
				n, err := session.ptmx.Read(buf)
				if err != nil {
					if err != io.EOF {
						log.Printf("Error reading from terminal: %v", err)
					}
					return
				}
				
				if debugMode {
					log.Printf("Read %d bytes from terminal: %q", n, string(buf[:n]))
				}
				
				select {
				case <-ctx.Done():
					return
				default:
				}
				
				// Choose message type based on data validity
				data := buf[:n]
				var messageType int
				if utf8.Valid(data) {
					messageType = websocket.TextMessage
					if debugMode {
						log.Printf("Sending as text message")
					}
				} else {
					messageType = websocket.BinaryMessage
					if debugMode {
						log.Printf("Sending as binary message")
					}
				}
				
				// Broadcast to all connections
				session.BroadcastToConnections(messageType, data)
			}
		}()
	}

	// Copy websocket input to terminal
	go func() {
		defer cancel()
		
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			var msg struct {
				Type string `json:"type"`
				Data string `json:"data"`
				Cols int    `json:"cols,omitempty"`
				Rows int    `json:"rows,omitempty"`
			}
			
			if err := c.ReadJSON(&msg); err != nil {
				// Don't log normal disconnection errors
				return
			}
			
			switch msg.Type {
			case "input":
				if err := session.writeInput([]byte(msg.Data)); err != nil {
					// Terminal write failed, probably because process died
					return
				}
			case "resize":
				if err := session.resize(msg.Cols, msg.Rows); err != nil {
					log.Printf("Error resizing terminal: %v", err)
				}
			}
		}
	}()

	// Wait for termination
	<-ctx.Done()
	log.Printf("WebSocket disconnected from session %s for user %s", sessionID, username)
}

func main() {
	// Parse command line flags
	debug := flag.Bool("debug", false, "Enable debug logging")
	configPath := flag.String("config", "", "Path to configuration file")
	flag.Parse()
	
	// Check environment variable as well
	if envDebug := os.Getenv("DEBUG"); envDebug != "" {
		debugMode = strings.ToLower(envDebug) == "true" || envDebug == "1"
	} else {
		debugMode = *debug
	}
	
	if debugMode {
		log.Println("Debug mode enabled")
	}

	// Load configuration
	var err error
	appConfig, err = config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize managers
	userManager = user.NewManager(appConfig.User.HomeDirBase, appConfig.User.Shell)
	sessionManager = session.NewManager(
		appConfig.Session.Secret,
		appConfig.Session.MaxAge,
		appConfig.Session.Secure,
		appConfig.Session.HttpOnly,
	)

	// Initialize OIDC handlers
	authHandlers, err = auth.NewHandlers(
		auth.OIDCConfig{
			ClientID:     appConfig.OIDC.ClientID,
			ClientSecret: appConfig.OIDC.ClientSecret,
			IssuerURL:    appConfig.OIDC.IssuerURL,
			RedirectURL:  appConfig.OIDC.RedirectURL,
			Scopes:       appConfig.OIDC.Scopes,
		},
		userManager,
		sessionManager,
	)
	if err != nil {
		log.Fatalf("Failed to initialize auth handlers: %v", err)
	}

	// Initialize terminal session manager
	initTerminalSessionManager()

	app := fiber.New()
	app.Use(logger.New())
	app.Use(auth.SecurityHeaders())
	app.Use(auth.RateLimitMiddleware(100, time.Minute))

	// Serve static files
	app.Static("/", ".", fiber.Static{
		Index: "index.html",
	})

	// Auth routes
	app.Get("/auth/login", authHandlers.Login)
	app.Get("/auth/callback", authHandlers.Callback)
	app.Get("/auth/logout", authHandlers.Logout)
	app.Get("/auth/user", authHandlers.UserInfo)

	// API routes
	app.Post("/api/session", authHandlers.RequireAuth, func(c *fiber.Ctx) error {
		sessionID := uuid.New().String()
		return c.JSON(fiber.Map{"sessionId": sessionID})
	})

	// WebSocket upgrade middleware
	app.Use("/ws", func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			c.Locals("allowed", true)
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})

	// WebSocket endpoint with authentication
	app.Get("/ws", authHandlers.RequireAuth, websocket.New(handleWebSocket))

	// Visual configuration endpoint
	app.Get("/api/visual-config", func(c *fiber.Ctx) error {
		// In a real implementation, this would load from ~/.terminalrc
		// For now, serve the default configuration
		return c.JSON(map[string]interface{}{
			"terminal": map[string]interface{}{
				"font_size":            14,
				"font_family":          "Monaco, Menlo, \"DejaVu Sans Mono\", \"Lucida Console\", monospace",
				"cursor_blink":         true,
				"scrollback":           1000,
				"allow_proposed_api":   true,
			},
			"theme": map[string]interface{}{
				"background":           "#000000",
				"foreground":           "#ffffff",
				"cursor":               "#ffffff",
				"cursor_accent":        "#000000",
				"selection_background": "#3366aa",
			},
		})
	})

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	addr := fmt.Sprintf("%s:%d", appConfig.Server.Host, appConfig.Server.Port)
	fmt.Printf("Server starting on http://%s\n", addr)
	if debugMode {
		fmt.Println("Debug mode: Use -debug flag or DEBUG=true environment variable")
	}
	log.Fatal(app.Listen(addr))
}