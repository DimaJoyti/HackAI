package domain

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID        uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Email     string     `json:"email" gorm:"uniqueIndex;not null"`
	Username  string     `json:"username" gorm:"uniqueIndex;not null"`
	Password  string     `json:"-" gorm:"not null"` // Never expose password in JSON
	FirstName string     `json:"first_name"`
	LastName  string     `json:"last_name"`
	Role      UserRole   `json:"role" gorm:"default:'user'"`
	Status    UserStatus `json:"status" gorm:"default:'active'"`

	// Profile information
	Avatar   string `json:"avatar"`
	Bio      string `json:"bio"`
	Company  string `json:"company"`
	Location string `json:"location"`
	Website  string `json:"website"`

	// Security settings
	TwoFactorEnabled  bool       `json:"two_factor_enabled" gorm:"default:false"`
	LastLoginAt       *time.Time `json:"last_login_at"`
	PasswordChangedAt time.Time  `json:"password_changed_at"`

	// Audit fields
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" gorm:"index"`
}

// UserRole defines user roles in the system
type UserRole string

const (
	UserRoleAdmin     UserRole = "admin"
	UserRoleModerator UserRole = "moderator"
	UserRoleUser      UserRole = "user"
	UserRoleGuest     UserRole = "guest"
)

// UserStatus defines user account status
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusInactive  UserStatus = "inactive"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusPending   UserStatus = "pending"
)

// UserSession represents an active user session
type UserSession struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	Token     string    `json:"-" gorm:"uniqueIndex;not null"` // JWT token hash
	DeviceID  string    `json:"device_id"`
	UserAgent string    `json:"user_agent"`
	IPAddress string    `json:"ip_address"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`

	// Relationships
	User User `json:"user" gorm:"foreignKey:UserID"`
}

// UserPermission represents granular permissions
type UserPermission struct {
	ID        uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index"`
	Resource  string     `json:"resource" gorm:"not null"`
	Action    string     `json:"action" gorm:"not null"`
	Granted   bool       `json:"granted" gorm:"default:true"`
	GrantedBy uuid.UUID  `json:"granted_by" gorm:"type:uuid"`
	GrantedAt time.Time  `json:"granted_at"`
	ExpiresAt *time.Time `json:"expires_at"`

	// Relationships
	User          User `json:"user" gorm:"foreignKey:UserID"`
	GrantedByUser User `json:"granted_by_user" gorm:"foreignKey:GrantedBy"`
}

// UserActivity represents user activity logs
type UserActivity struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	Action    string    `json:"action" gorm:"not null"`
	Resource  string    `json:"resource"`
	Details   string    `json:"details"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`

	// Relationships
	User User `json:"user" gorm:"foreignKey:UserID"`
}

// UserRepository defines the interface for user data access
type UserRepository interface {
	Create(user *User) error
	GetByID(id uuid.UUID) (*User, error)
	GetByEmail(email string) (*User, error)
	GetByUsername(username string) (*User, error)
	Update(user *User) error
	Delete(id uuid.UUID) error
	List(limit, offset int) ([]*User, error)
	Search(query string, limit, offset int) ([]*User, error)

	// Session management
	CreateSession(session *UserSession) error
	GetSession(token string) (*UserSession, error)
	DeleteSession(token string) error
	DeleteUserSessions(userID uuid.UUID) error

	// Permissions
	GrantPermission(permission *UserPermission) error
	RevokePermission(userID uuid.UUID, resource, action string) error
	GetUserPermissions(userID uuid.UUID) ([]*UserPermission, error)
	HasPermission(userID uuid.UUID, resource, action string) (bool, error)

	// Activity logging
	LogActivity(activity *UserActivity) error
	GetUserActivity(userID uuid.UUID, limit, offset int) ([]*UserActivity, error)
}

// UserUseCase defines the interface for user business logic
type UserUseCase interface {
	Register(email, username, password, firstName, lastName string) (*User, error)
	Login(emailOrUsername, password string) (*User, string, error) // returns user, token, error
	Logout(token string) error
	GetProfile(userID uuid.UUID) (*User, error)
	UpdateProfile(userID uuid.UUID, updates map[string]interface{}) (*User, error)
	ChangePassword(userID uuid.UUID, oldPassword, newPassword string) error
	ResetPassword(email string) error
	VerifyToken(token string) (*User, error)

	// Admin functions
	ListUsers(limit, offset int) ([]*User, error)
	SearchUsers(query string, limit, offset int) ([]*User, error)
	UpdateUserRole(userID uuid.UUID, role UserRole) error
	UpdateUserStatus(userID uuid.UUID, status UserStatus) error

	// Permissions
	GrantPermission(userID uuid.UUID, resource, action string, grantedBy uuid.UUID) error
	RevokePermission(userID uuid.UUID, resource, action string) error
	CheckPermission(userID uuid.UUID, resource, action string) (bool, error)

	// Activity
	GetUserActivity(userID uuid.UUID, limit, offset int) ([]*UserActivity, error)
}

// TableName returns the table name for User model
func (User) TableName() string {
	return "users"
}

// TableName returns the table name for UserSession model
func (UserSession) TableName() string {
	return "user_sessions"
}

// TableName returns the table name for UserPermission model
func (UserPermission) TableName() string {
	return "user_permissions"
}

// TableName returns the table name for UserActivity model
func (UserActivity) TableName() string {
	return "user_activities"
}

// IsAdmin checks if user has admin role
func (u *User) IsAdmin() bool {
	return u.Role == UserRoleAdmin
}

// IsModerator checks if user has moderator or admin role
func (u *User) IsModerator() bool {
	return u.Role == UserRoleModerator || u.Role == UserRoleAdmin
}

// IsActive checks if user account is active
func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}

// FullName returns the user's full name
func (u *User) FullName() string {
	if u.FirstName == "" && u.LastName == "" {
		return u.Username
	}
	return u.FirstName + " " + u.LastName
}

// IsExpired checks if session is expired
func (s *UserSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsExpired checks if permission is expired
func (p *UserPermission) IsExpired() bool {
	return p.ExpiresAt != nil && time.Now().After(*p.ExpiresAt)
}

// IsValid checks if permission is valid (granted and not expired)
func (p *UserPermission) IsValid() bool {
	return p.Granted && !p.IsExpired()
}
