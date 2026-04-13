package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/processor"
)

var matchJSON bool

var matchCmd = &cobra.Command{
	Use:   "match [file|folder]",
	Short: "Show all matched files and keys",
	Long: `Show all files matching the configured patterns and all keys matching
the configured key patterns, regardless of encryption state.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runMatch,
}

func init() {
	rootCmd.AddCommand(matchCmd)
	matchCmd.Flags().BoolVar(&matchJSON, "json", false, "Output in JSON format")
}

func runMatch(cmd *cobra.Command, args []string) {
	var singleFile string
	cfgPath := resolvedConfigPath

	if len(args) > 0 {
		if filePath != "" {
			fmt.Fprintf(os.Stderr, "Error: cannot use both positional argument and --file flag\n")
			os.Exit(1)
		}

		var err error
		cfgPath, singleFile, err = ResolveTarget(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	proc, err := processor.NewProcessor(cfg, func() ([]age.Identity, error) {
		return LoadDecryptionIdentity(cfg, "", "", false, false)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var filesWithFormat []FileWithFormat
	if singleFile != "" {
		format, matches, err := cfg.MatchesFileWithFormat(singleFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking file pattern: %v\n", err)
			os.Exit(1)
		}
		if !matches {
			relPath, _ := filepath.Rel(cfg.ConfigDir(), singleFile)
			if relPath == "" || strings.HasPrefix(relPath, "..") {
				fmt.Fprintf(os.Stderr, "Error: file %s is outside config directory %s\n", singleFile, cfg.ConfigDir())
			} else {
				fmt.Fprintf(os.Stderr, "Error: file %q does not match any pattern in files list\n", relPath)
			}
			os.Exit(1)
		}
		filesWithFormat = []FileWithFormat{{Path: singleFile, Format: format}}
	} else {
		filesWithFormat, err = GetFilesToProcessWithFormat(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	if len(filesWithFormat) == 0 {
		if matchJSON {
			fmt.Println(`{"files":{}}`)
		} else {
			fmt.Fprintf(os.Stderr, "No files matched the configured patterns\n")
		}
		os.Exit(0)
	}

	type keyInfo struct {
		Name      string `json:"name"`
		Encrypted bool   `json:"encrypted"`
	}

	type fileResult struct {
		keys []keyInfo
	}

	results := make(map[string]*fileResult)

	for _, f := range filesWithFormat {
		relPath, _ := filepath.Rel(cfg.ConfigDir(), f.Path)
		if relPath == "" {
			relPath = f.Path
		}

		matches, err := proc.MatchFile(f.Path, f.Format)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking %s: %v\n", relPath, err)
			os.Exit(1)
		}

		fr := &fileResult{}
		for _, m := range matches {
			name := strings.Join(m.Path, ".")
			if name == "" {
				name = m.KeyName
			}
			fr.keys = append(fr.keys, keyInfo{Name: name, Encrypted: m.Encrypted})
		}
		results[relPath] = fr
	}

	if matchJSON {
		jsonFiles := make(map[string][]keyInfo)
		for path, fr := range results {
			jsonFiles[path] = fr.keys
			if jsonFiles[path] == nil {
				jsonFiles[path] = []keyInfo{}
			}
		}
		output := struct {
			Files map[string][]keyInfo `json:"files"`
		}{Files: jsonFiles}
		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonBytes))
	} else {
		for path, fr := range results {
			fmt.Printf("%s:\n", path)
			if len(fr.keys) == 0 {
				fmt.Println("  (no matching keys)")
			}
			for _, k := range fr.keys {
				status := ""
				if k.Encrypted {
					status = " [encrypted]"
				}
				fmt.Printf("  - %s%s\n", k.Name, status)
			}
		}
	}
}
