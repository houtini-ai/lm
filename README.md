# Houtini LM - LM Studio MCP Server with Expert Prompt Library and Custom Prompting

**Version**: 1.0.1  
**Your unlimited AI companion: This MCP server connects Claude to LM Studio for code analysis, generation, and creativity**

Transform your development workflow with our expert-level prompt library for code analysis, professional documentation generation, and creative project scaffolding - all running locally without API costs. For developers, vibe coders and creators alike.

## What This Does

Houtini LM **saves your Claude context window** by offloading detailed analysis tasks to LM Studio locally or on your company network whilst Claude focuses on strategy and complex problem-solving. Think of it as your intelligent coding assistant that never runs out of tokens.

**Perfect for:**
- 🔍 **Code analysis** - Deep insights into quality, security, and architecture
- 📝 **Documentation generation** - Professional docs from code analysis
- 🏗️ **Project scaffolding** - Complete applications, themes, and components
- 🎮 **Creative projects** - Games, CSS art, and interactive experiences
- 🛡️ **Security audits** - OWASP compliance and vulnerability detection

## Quick Start Prompt Guide

Once installed, simply use natural language prompts with Claude:

```
Use houtini-lm to analyse the code quality in C:/my-project/src/UserAuth.js
```

```
Generate comprehensive unit tests using houtini-lm for my React component at C:/components/Dashboard.jsx
```

```
Use houtini-lm to create a WordPress plugin called "Event Manager" with custom post types and admin interface
```

```
Audit the security of my WordPress theme using houtini-lm at C:/themes/my-theme
```

```
Create a CSS art generator project using houtini-lm with space theme and neon colours
```

```
Use houtini-lm to convert my JavaScript file to TypeScript with strict mode enabled
```

```
Generate responsive HTML components using houtini-lm for a pricing card with dark mode support
```

## Prerequisites

**Essential Requirements:**

1. **LM Studio** - Download from [lmstudio.ai](https://lmstudio.ai)
   - Must be running at `ws://127.0.0.1:1234`
   - Model loaded and ready (13B+ parameters recommended)

2. **Desktop Commander MCP** - Essential for file operations
   - Repository: [DesktopCommanderMCP](https://github.com/wonderwhy-er/DesktopCommanderMCP)
   - Required for reading files and writing generated code

3. **Node.js 24.6.0 or later** - For MCP server functionality
   - Download from [nodejs.org](https://nodejs.org)

4. **Claude Desktop** - For the best experience
   - Download from [claude.ai/download](https://claude.ai/download)

## Installation

### 1. Install Dependencies

```bash
# Clone the repository
git clone https://github.com/houtini-ai/lm.git
cd lm

# Install Node.js dependencies
npm install
```

### 2. Configure Claude Desktop

Add to your Claude Desktop configuration file:

**Windows**: `%APPDATA%/Claude/claude_desktop_config.json`  
**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "houtini-lm": {
      "command": "node",
      "args": ["path/to/houtini-lm/index.js"],
      "env": {
        "LLM_MCP_ALLOWED_DIRS": "C:/your-projects,C:/dev,C:/websites"
      }
    }
  }
}
```

### 3. Start LM Studio

1. Launch LM Studio
2. Load a model (13B+ parameters recommended for best results)
3. Start the server at `ws://127.0.0.1:1234`
4. Verify the model is ready and responding

### 4. Verify Installation

Restart Claude Desktop, then test with:

```
Use houtini-lm health check to verify everything is working
```

## Available Functions

### 🔍 Analysis Functions (17 functions)
- **`analyze_single_file`** - Deep code analysis and quality assessment
- **`count_files`** - Project structure with beautiful markdown trees
- **`find_unused_files`** - Dead code detection with risk assessment
- **`security_audit`** - OWASP compliance and vulnerability scanning
- **`analyze_dependencies`** - Circular dependencies and unused imports
- And 12 more specialized analysis tools...

### 🛠️ Generation Functions (10 functions)
- **`generate_unit_tests`** - Comprehensive test suites with framework patterns
- **`generate_documentation`** - Professional docs from code analysis
- **`convert_to_typescript`** - JavaScript to TypeScript with type safety
- **`generate_wordpress_plugin`** - Complete WordPress plugin creation
- **`generate_responsive_component`** - Accessible HTML/CSS components
- And 5 more generation tools...

### 🎮 Creative Functions (3 functions)
- **`css_art_generator`** - Pure CSS art and animations
- **`arcade_game`** - Complete playable HTML5 games
- **`create_text_adventure`** - Interactive fiction with branching stories

### ⚙️ System Functions (5 functions)
- **`health_check`** - Verify LM Studio connection
- **`list_functions`** - Discover all available functions
- **`resolve_path`** - Path analysis and suggestions
- And 2 more system utilities...

## Documentation

**Complete guides available:**
- [Analysis Functions Guide](docs/analysis-functions-md.md) - All 17 analysis tools
- [Generation Functions Guide](docs/generation-functions-md.md) - All 10 creation tools  
- [Creative Functions Guide](docs/creative-functions-md.md) - Games and art tools
- [System Functions Guide](docs/system-functions-md.md) - Utilities and diagnostics
- [Complete User Guide](docs/user-guide-md.md) - Comprehensive usage manual

## Recommended Setup

**For Professional Development:**
- **CPU**: 8-core or better (for local LLM processing)
- **RAM**: 32GB (24GB for model, 8GB for development)
- **Storage**: SSD with 100GB+ free space
- **Model**: Qwen2.5-Coder-14B-Instruct or similar

**Performance Tips:**
- Use 13B+ parameter models for professional-quality results
- Configure `LLM_MCP_ALLOWED_DIRS` to include your project directories
- Install Desktop Commander MCP for complete file operation support
- Keep LM Studio running and model loaded for instant responses

## Version History

### Version 1.0.0 (Current)
- ✅ Complete function library (35+ functions)
- ✅ Professional documentation system
- ✅ WordPress-specific tools and auditing
- ✅ Creative project generators
- ✅ Comprehensive security analysis
- ✅ TypeScript conversion and test generation
- ✅ Cross-file integration analysis

## License

**MIT License** - Use this project freely for personal and commercial projects. See [LICENSE](LICENSE) for details.

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on:
- Code standards and patterns
- Testing requirements
- Documentation updates
- Issue reporting

## Support

- **Issues**: [GitHub Issues](https://github.com/houtini-ai/lm/issues)
- **Discussions**: [GitHub Discussions](https://github.com/houtini-ai/lm/discussions)
- **Documentation**: Complete guides in the `docs/` directory

---

**Ready to supercharge your development workflow?** Install Houtini LM and start building amazing things with unlimited local AI assistance.

*Built for developers who think clearly but can't afford to think expensively.*