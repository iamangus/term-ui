# Terminal Web Application with OIDC Authentication

A secure web-based terminal application that provides browser-based shell access with OpenID Connect (OIDC) authentication and automatic Linux user management.

## Features

- **OIDC Authentication**: Support for any OpenID Connect provider (Google, Azure AD, Okta, Keycloak, etc.)
- **Automatic User Management**: Creates Linux users on first login with proper home directories
- **Secure WebSocket**: All terminal sessions require authentication
- **Multi-user Support**: Each user gets their own isolated terminal sessions
- **Mobile Optimized**: Responsive design with touch-friendly controls
- **Security First**: Rate limiting, security headers, and proper session management

## Quick Start

### 1. Configuration

Copy the example configuration file:

```bash
cp config.json.example config.json
```

Edit `config.json` with your OIDC provider details:

```json
{
  "oidc": {
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "issuer_url": "https://your-oidc-provider.com",
    "redirect_url": "http://localhost:8080/auth/callback",
    "scopes": ["openid", "profile", "email"]
  },
  "server": {
    "host": "localhost",
    "port": 8080
  },
  "session": {
    "secret": "your-very-secure-secret-key-change-this-in-production",
    "max_age": 86400,
    "secure": false,
    "http_only": true
  },
  "user": {
    "home_dir_base": "/home",
    "shell": "/bin/bash"
  }
}
```

### 2. Install Dependencies

```bash
go mod tidy
```

### 3. Run the Application

```bash
# Development mode
go run main.go -debug

# Production mode
go run main.go

# With custom config
go run main.go -config /path/to/config.json
```

### 4. Access the Terminal

Open your browser to `http://localhost:8080` and authenticate with your OIDC provider.

## OIDC Provider Setup

### Google OAuth 2.0

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URI: `http://localhost:8080/auth/callback`
6. Use the client ID and secret in your config

### Azure Active Directory

1. Go to Azure Portal > Azure Active Directory > App registrations
2. Register new application
3. Add redirect URI: `http://localhost:8080/auth/callback`
4. Note the Application (client) ID and Directory (tenant) ID
5. Create client secret
6. Update config:
   ```json
   "issuer_url": "https://login.microsoftonline.com/{tenant-id}/v2.0",
   "client_id": "{application-id}",
   "client_secret": "{client-secret}"
   ```

### Keycloak

1. Create a new client in your Keycloak realm
2. Set Valid Redirect URIs: `http://localhost:8080/auth/callback`
3. Use the client credentials in your config
4. Update issuer_url: `https://your-keycloak-domain.com/realms/your-realm`

## Security Considerations

### Production Deployment

1. **HTTPS**: Always use HTTPS in production
2. **Session Secret**: Change the default session secret
3. **Rate Limiting**: Adjust rate limits based on your needs
4. **User Permissions**: Ensure the application runs with appropriate permissions
5. **Firewall**: Restrict access to necessary ports only

### User Management

The application automatically creates Linux users on first login:
- Username is derived from email (sanitized)
- Home directory is created at `/home/{username}`
- Default shell is `/bin/bash` (configurable)
- Users are created with standard system useradd command

### Permissions Required

The application needs to:
- Create system users (requires root or sudo)
- Set user credentials for process execution
- Access user home directories

For production, consider running with a dedicated service account that has:
```bash
# Add user with limited sudo for useradd
sudo visudo
# Add: terminal ALL=(ALL) NOPASSWD: /usr/sbin/useradd
```

## Configuration Options

### Application Configuration (config.json)
| Option | Description | Default |
|--------|-------------|---------|
| `oidc.client_id` | OIDC client ID | Required |
| `oidc.client_secret` | OIDC client secret | Required |
| `oidc.issuer_url` | OIDC provider URL | Required |
| `oidc.redirect_url` | Callback URL | Required |
| `oidc.scopes` | OIDC scopes to request | `["openid", "profile", "email"]` |
| `server.host` | Server bind address | `localhost` |
| `server.port` | Server port | `8080` |
| `session.secret` | JWT signing secret | Required |
| `session.max_age` | Session duration (seconds) | `86400` |
| `session.secure` | Secure cookies (HTTPS only) | `false` |
| `session.http_only` | HTTP-only cookies | `true` |
| `user.home_dir_base` | Base directory for user homes | `/home` |
| `user.shell` | Default shell for new users | `/bin/bash` |

### Visual Configuration (~/.terminalrc)
Create `~/.terminalrc` to customize the terminal appearance:

```json
{
  "terminal": {
    "font_size": 14,
    "font_family": "Monaco, Menlo, \"DejaVu Sans Mono\", \"Lucida Console\", monospace",
    "cursor_blink": true,
    "scrollback": 1000,
    "allow_proposed_api": true
  },
  "theme": {
    "background": "#000000",
    "foreground": "#ffffff",
    "cursor": "#ffffff",
    "cursor_accent": "#000000",
    "selection_background": "#3366aa"
  }
}
```

### Available Themes

**Default (Dark)**
```json
"theme": {
  "background": "#000000",
  "foreground": "#ffffff",
  "cursor": "#ffffff",
  "cursor_accent": "#000000",
  "selection_background": "#3366aa"
}
```

**Solarized Dark**
```json
"theme": {
  "background": "#002b36",
  "foreground": "#839496",
  "cursor": "#93a1a1",
  "cursor_accent": "#002b36",
  "selection_background": "#073642"
}
```

**Monokai**
```json
"theme": {
  "background": "#272822",
  "foreground": "#f8f8f2",
  "cursor": "#f8f8f0",
  "cursor_accent": "#272822",
  "selection_background": "#49483e"
}
```</search>
</search_and_replace>

## Development

### Project Structure

```
terminal/
├── main.go                 # Application entry point
├── internal/
│   ├── auth/              # OIDC authentication handlers
│   ├── config/            # Configuration management
│   ├── session/           # JWT session management
│   └── user/              # Linux user management
├── index.html             # Frontend interface
├── config.json.example    # Configuration template
├── go.mod                 # Go module definition
└── README.md             # This file
```

### Testing

1. **Unit Tests**: Run `go test ./...`
2. **Integration Tests**: Test with your OIDC provider
3. **Security Tests**: Check headers and rate limiting

### Debugging

Enable debug mode:
```bash
go run main.go -debug
# or
DEBUG=true go run main.go
```

## Troubleshooting

### Common Issues

1. **"failed to create user"**: Ensure the application has permission to run `useradd`
2. **"invalid redirect URI"**: Check your OIDC provider's redirect URI configuration
3. **"session secret too short"**: Use a longer secret (minimum 32 characters)
4. **WebSocket connection fails**: Check firewall and proxy settings

### Logs

The application logs to stdout. Check logs for:
- Authentication flow issues
- User creation problems
- WebSocket connection errors

### OIDC Debugging

Enable debug mode to see detailed OIDC flow logs including:
- Token exchange details
- User claims
- Session creation

## License

MIT License - see LICENSE file for details.