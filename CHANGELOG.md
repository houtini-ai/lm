# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.10] - 2025-01-09

### Fixed
- **Increased timeout to 5 minutes** - Changed LM Studio timeout from 120000ms (2 minutes) to 300000ms (5 minutes)
  - Prevents timeouts on large multi-file analysis and complex generation tasks
  - Improves reliability for slower local models or heavily loaded systems
  - Addresses timeout issues with project-wide security audits and creative functions
  - Particularly beneficial for WordPress plugin/theme analysis and large codebase operations

## [4.1.0] - 2025-08-29

### 🎉 MAJOR RELEASE - 3-Stage Architecture Complete

### Added
- **Complete 3-Stage Architecture Deployment** - All multifile plugins now use the proven 3-stage prompt architecture
  - `ThreeStagePromptManager` integration across all 4 multifile plugins
  - `getPromptStages()` method with structured prompt stages (System+Context, Data Payload, Output Instructions)
  - `executeSinglePass()` and `executeWithChunking()` methods for intelligent operation sizing
  - Dynamic context detection from LM Studio (23,832 tokens from Qwen 3 Coder 30B)

### Changed  
- **Architecture Consistency** - Eliminated dual chunking conflicts throughout codebase
  - Context Window Manager is now the sole chunking authority
  - Single, consistent 3-stage chunking system across all multifile operations
  - Smart prompt staging for optimal LLM utilization
  - Consistent error handling and response formatting

### Fixed
- **100% Success Rate** - All multifile functions tested and verified working:
  - ✅ `compare_integration`: Perfect integration analysis with detailed findings
  - ✅ `trace_execution_path`: Successful 4-chunk processing with execution traces  
  - ✅ `diff_method_signatures`: Accurate signature compatibility analysis
  - ✅ `find_pattern_usage`: Pattern detection across entire codebase

### Performance
- **Context Preservation** - Eliminated hardcoded limits in favor of dynamic detection
- **Scalable Operations** - Support for any operation size through intelligent chunking
- **Memory Efficiency** - Optimized prompt staging reduces token waste
- **Reliability** - Robust error handling and fallback mechanisms

## [4.0.1] - 2025-08-29

### Fixed
- **Cache Management Tools Registration** - Fixed plugin loader to properly register cache management functions
  - `clear_analysis_cache` and `get_cache_statistics` now properly available as MCP tools
  - Fixed file:// URL format issue in plugin loader for Windows paths
  - Build process now correctly compiles and exposes all 17 functions

### Added
- **100% Function Completion** - All 17 functions from functional specification v4.0 now working:
  - 4 Analysis functions: analyze_single_file, security_audit, analyze_project_structure, analyze_n8n_workflow
  - 6 Generation functions: generate_unit_tests, generate_documentation, suggest_refactoring, generate_wordpress_plugin, convert_to_typescript, generate_responsive_component
  - 4 Multi-file functions: compare_integration, trace_execution_path, find_pattern_usage, diff_method_signatures
  - 3 System functions: health_check, clear_analysis_cache, get_cache_statistics

### Changed
- **Documentation Updates** - Comprehensive README.md updates to reflect 100% completion status
  - Updated function counts and categorization
  - Added completion badges and status indicators
  - Improved tool organization and descriptions
  - Token savings data refreshed

## [4.0.0] - 2025-08-28

### Changed
- **BREAKING**: Renamed `analyze_code_structure` to `analyze_single_file` for clarity
  - The function now explicitly indicates it analyses a single file, not a directory
  - Use `analyze_project_structure` for multi-file/directory analysis
  - All enum references updated from `CODE_STRUCTURE` to `ANALYZE_SINGLE_FILE`

## [3.0.4] - 2025-08-27

### Fixed
- **Critical streaming issue** - Resolved `[object Object]` output when processing LLM responses
- **LM Studio SDK compatibility** - Proper handling of object-based chunks with `content` property
- **Qwen model support** - Fixed streaming for Qwen thinking models that output structured chunks

### Added
- **Stream handler integration** - Robust chunk processing for multiple streaming formats
- **Test scripts**:
  - `test-llm-streaming.mjs` - Direct LLM streaming validation
  - `test-streaming-fix.mjs` - MCP protocol streaming test
- **Comprehensive streaming support** for:
  - LM Studio object chunks
  - OpenAI-style responses
  - Plain text strings
  - Unknown object formats with JSON fallback

### Changed
- Replaced simple string concatenation with `handleLLMResponse` function
- Improved error handling for malformed chunks

## [3.0.3] - 2025-08-26

### Fixed
- Added missing `health_check` tool definition (handler existed but tool wasn't registered)
- Added empty handlers for `resources/list` and `prompts/list` to prevent "Method not found" errors in Claude logs
- These optional MCP protocol methods now return empty arrays as expected

### Added
- **Diagnostic Tools**:
  - `diagnostics/run-diagnostics.mjs` - Comprehensive system diagnostic tool that checks:
    - Node.js version compatibility
    - LM Studio connection and loaded models
    - Claude configuration validity
    - Multiple Claude process detection
    - MCP server startup capability
    - Generates detailed `diagnostic-report.json`
  - `diagnostics/check-claude-processes.mjs` - Windows-specific tool to detect multiple Claude.exe processes
- **Documentation Updates**:
  - Added "Known Issues" section to TROUBLESHOOTING.md
  - Documented multiple Claude.exe processes issue and solution
  - Documented "Method not found" errors and resolution
  - Added diagnostic tool usage instructions

### Changed
- Enhanced troubleshooting guide with new debugging tools section
- Improved error diagnostics and user guidance

## [3.0.2] - 2025-08-23

### Fixed
- Added missing shebang (`#!/usr/bin/env node`) to dist/index.js for NPX execution
- Fixed NPM package execution on Windows
- Added post-build script to ensure shebang persists after TypeScript compilation

## [3.0.1] - 2025-08-23

### Changed
- Cleaned up root directory by removing development and handover files
- Updated .gitignore to prevent future development file commits
- Repository now contains only essential files for npm package and GitHub

### Removed
- Development documentation files (handover, implementation notes)
- Test files used during development (test-enhanced*.mjs)
- Backup directories and migration scripts
- 18 unnecessary files total

## [3.0.0] - 2025-08-25

### Added
- **Context-aware prompts** for enhanced code analysis
  - Support for 11 project types (WordPress, React, n8n, Node.js, etc.)
  - Framework-specific best practices and suggestions
  - Optional context parameter maintains backward compatibility
- **5 new powerful tools**:
  - `generate_wordpress_plugin` - Complete WordPress plugin generator with Brain Monkey test support
  - `analyze_n8n_workflow` - n8n workflow optimization and analysis
  - `generate_responsive_component` - Accessible, responsive component generator
  - `convert_to_typescript` - Intelligent JavaScript to TypeScript converter
  - `security_audit` - Project-specific security vulnerability scanner
- **90% token savings** through intelligent task delegation
- **Enhanced type system** with comprehensive TypeScript definitions
- **Project-specific security checklists** for each supported framework

### Changed
- **RENAMED**: `analyze_code_structure` is now `analyze_single_file` for clarity
  - `analyze_single_file` - Now provides framework-specific insights for a single file
  - Note: Use `analyze_project_structure` for multi-file/directory analysis
- Enhanced existing tools with optional context support:
  - `generate_unit_tests` - Creates framework-aware test suites
  - `generate_documentation` - Generates audience-appropriate documentation
  - `suggest_refactoring` - Offers project-specific improvements
- Improved prompt quality for better LLM responses
- Better error messages with context-aware suggestions

### Technical Improvements
- Modular prompt system for easier maintenance
- Comprehensive type definitions for all contexts
- Enhanced prompt templates with domain knowledge
- Improved code organization and separation of concerns

## [2.2.2] - 2025-08-25

### Fixed
- Fixed NPX execution on Windows by normalizing file paths
- Handle forward/backward slash differences between import.meta.url and process.argv
- Fixed "server transport closed unexpectedly" error when using NPX

## [2.2.1] - 2025-08-25

### Fixed
- Added missing bin field to enable NPX execution
- Fixed "could not determine executable to run" error
- Updated examples to show NPX usage

### Added
- Clean and rebuild scripts for easier development

## [2.2.0] - 2025-08-25

### Fixed
- Restored all missing tool definitions in setupHandlers
- Fixed issue where only health_check was being registered

### Added
- All 10 tools now properly available:
  - analyze_single_file
  - generate_unit_tests
  - generate_documentation
  - suggest_refactoring
  - detect_patterns
  - validate_syntax
  - suggest_variable_names
  - analyze_file
  - analyze_csv_data
  - health_check

## [2.1.0] - 2025-08-24

### Added
- **Security Features**:
  - Path validation to prevent unauthorized file access
  - Configurable allowed directories via LLM_MCP_ALLOWED_DIRS
  - Path traversal protection
  - File size limits (configurable, default 10MB)
- **Configuration options**:
  - Environment variable support for security settings
  - Configurable retry logic
  - Adjustable timeout settings

### Fixed
- Thinking tag regex for better response parsing
- TypeScript strict mode compliance
- Better error handling for invalid paths

### Changed
- Improved security posture with opt-in directory access
- Better error messages for permission issues

## [2.0.0] - 2025-08-23

### Added
- **File attachment support** - Analyze files directly without reading content first
- **LM Studio SDK integration** - Replaced axios with official @lmstudio/sdk
- **New tools**:
  - `analyze_file` - General file analysis with custom instructions
  - `analyze_csv_data` - CSV filtering and analysis
- **Streaming support** for better performance
- **Enhanced error handling** with better LM Studio status detection

### Changed
- Complete rewrite using LM Studio SDK
- Improved connection handling and retry logic
- Better model detection and validation

### Removed
- Axios dependency (replaced with LM Studio SDK)
- Manual HTTP request handling

## [1.0.0] - 2025-08-22

### Initial Release
- Basic code analysis tools
- Unit test generation
- Documentation generation
- Refactoring suggestions
- Pattern detection
- Bug finding
- Variable naming suggestions
- Basic LM Studio integration via HTTP

## Migration Notes

### Upgrading to v3.0.0
- No breaking changes - all existing code continues to work
- To use new context features, add optional `context` parameter
- New tools available immediately after upgrade
- See [Migration Guide](MIGRATION_GUIDE_V3.md) for detailed upgrade instructions

### Upgrading to v2.0.0
- Update LM Studio URL from http:// to ws:// protocol
- File analysis now available through new tools
- Check [Migration Guide](MIGRATION_GUIDE.md) for details
