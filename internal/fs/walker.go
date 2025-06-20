package fs

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/TFMV/tightrope/pkg"
	"github.com/rs/zerolog"
)

// Walker handles directory traversal and file filtering
type Walker struct {
	extensions map[string]bool
	logger     zerolog.Logger
}

// NewWalker creates a new file system walker
func NewWalker() *Walker {
	extensions := make(map[string]bool)
	for _, ext := range pkg.SupportedExtensions {
		extensions[ext] = true
	}

	return &Walker{
		extensions: extensions,
		logger:     zerolog.New(os.Stderr).With().Timestamp().Logger(),
	}
}

// Walk recursively traverses the directory and returns paths to configuration files
func (w *Walker) Walk(rootPath string) ([]string, error) {
	var configFiles []string

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			w.logger.Warn().
				Err(err).
				Str("path", path).
				Msg("Error accessing path during walk")
			return nil // Continue walking despite errors
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip hidden files and directories
		if strings.HasPrefix(info.Name(), ".") {
			return nil
		}

		// Check if file has supported extension
		ext := strings.ToLower(filepath.Ext(path))
		if w.extensions[ext] {
			configFiles = append(configFiles, path)
			w.logger.Debug().
				Str("file", path).
				Str("extension", ext).
				Msg("Found configuration file")
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	w.logger.Info().
		Int("count", len(configFiles)).
		Str("root_path", rootPath).
		Msg("Directory walk completed")

	return configFiles, nil
}

// IsConfigFile checks if a file has a supported configuration extension
func (w *Walker) IsConfigFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return w.extensions[ext]
}

// GetRelativePath returns the relative path from the root to the target
func GetRelativePath(root, target string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}

	relPath, err := filepath.Rel(absRoot, absTarget)
	if err != nil {
		return "", err
	}

	return relPath, nil
}
