// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

package cli

// SHA256 checksums for 1Password CLI v2.31.1
// SECURITY NOTE: These checksums should be verified against official releases
// and updated whenever the CLI version changes. Always verify checksums from
// trusted sources before updating these values.
//
// Last verified: 2025-07-28
// Source: Official 1Password CLI downloads from cache.agilebits.com
// Verification method: Downloaded and calculated SHA256 for each platform binary
const (
	// DefaultCLIVersion is the default 1Password CLI version
	DefaultCLIVersion = "2.31.1"

	// Known SHA256 checksums for 1Password CLI v2.31.1
	SHA256LinuxAMD64 = "0fd8da9c6b6301781f50ef57cebbfd7d42d072777bcb4649ef5b6d360629b876" // Linux AMD64 v2.31.1
	// SHA256LinuxAMD64 = "03a6c4c01e395b673712a636da63ad9c951eb7542839a278b08a8f1b580654ac" // Linux AMD64 v2.31.1
	SHA256LinuxARM64   = "47bcd4dbeacefcd01ae8c913e61721ae71ac4f6a0b9150f48467ff719d494ff7" // Linux ARM64 v2.31.1
	SHA256DarwinAMD64  = "019f37e33a6d4f7824cda14eee5e24c2947d58d94ed7dd3b3fc3cbcd644647df" // macOS AMD64 v2.31.1
	SHA256DarwinARM64  = "71d38ddee25d34a9159b81d8c16844c3869defd7cc1563cc8f216a20439ceba4" // macOS ARM64 v2.31.1
	SHA256WindowsAMD64 = "9e54520aa136ecd6bc7082ec719b68f00bd23cb575c6e787d62f34cc44895bbb" // Windows AMD64 v2.31.1

	// Platform identifiers
	PlatformLinuxAMD64   = "linux_amd64"
	PlatformLinuxARM64   = "linux_arm64"
	PlatformDarwinAMD64  = "darwin_amd64"
	PlatformDarwinARM64  = "darwin_arm64"
	PlatformWindowsAMD64 = "windows_amd64"
)
