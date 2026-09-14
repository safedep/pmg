package platform

// OwnershipRestoreRemedy returns help text and the command that restores write
// access to dir after a privileged run created it. Unix uses chown. Windows
// uses takeown then icacls.
func OwnershipRestoreRemedy(dir string) (help, command string) { return ownershipRestoreRemedy(dir) }

// LeakedConfigDirRemedy returns help text and a one-line fix for a config
// directory that resolved outside the user's home because an environment
// variable leaked from another account. Unix names XDG_CONFIG_HOME. Windows
// names APPDATA.
func LeakedConfigDirRemedy(dir string) (help, fix string) { return leakedConfigDirRemedy(dir) }

// DefaultEditor is the fallback editor command when $VISUAL and $EDITOR are
// both unset. Unix returns vi when it is on PATH, or empty when it is not.
// Windows returns notepad, which is always present.
func DefaultEditor() string { return defaultEditor() }

// DefaultShell is the user's shell when $SHELL is unset and the parent process
// gives no answer. macOS uses zsh. Other systems use bash.
func DefaultShell() string { return defaultShell() }

// BashUsesLoginShell reports whether the terminal starts bash as a login shell
// by default, which does not read .bashrc. macOS Terminal does, so PMG writes
// .bash_profile there.
func BashUsesLoginShell() bool { return bashUsesLoginShell() }
