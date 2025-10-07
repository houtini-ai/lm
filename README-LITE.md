# Houtini LM Lite

A streamlined MCP server for offloading custom prompts to LM Studio. Full user control over prompt execution with zero configuration complexity.

## Philosophy

The lite version focuses on one thing: giving you complete control over your prompts while offloading execution to local LLMs. No preset libraries, no complex configurations - just direct prompt execution.

## Features

- **Custom Prompt Execution**: Complete control over your prompts
- **File-based Prompts**: Load prompts from files with variable substitution  
- **Batch Processing**: Execute multiple prompts in sequence
- **Zero Configuration**: Works out of the box with sensible defaults
- **Health Checking**: Built-in connection verification

## Installation

1. Ensure LM Studio is running with server enabled (default: http://localhost:1234)
2. Load a model in LM Studio
3. Build the lite version:

```bash
npm install
npm run build -- --project tsconfig-lite.json
```

## Claude Desktop Configuration

Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "houtini-lm-lite": {
      "command": "node",
      "args": ["C:/MCP/houtini-lm/dist/index-lite.js"],
      "env": {
        "LM_STUDIO_URL": "http://localhost:1234"
      }
    }
  }
}
```

## Usage

### Custom Prompt

Execute any prompt with full control:

```
Tool: custom_prompt
Arguments:
{
  "prompt": "Write a detailed analysis of...",
  "context": "Optional background information",
  "temperature": 0.7,
  "maxTokens": 4096,
  "systemPrompt": "You are a helpful assistant"
}
```

### File-based Prompts

Load prompts from files with variable substitution:

```
Tool: execute_file_prompt
Arguments:
{
  "filePath": "C:/prompts/analysis.txt",
  "variables": {
    "topic": "machine learning",
    "depth": "comprehensive"
  },
  "temperature": 0.8
}
```

Example prompt file:
```
Provide a {{depth}} analysis of {{topic}} including:
- Core concepts
- Current trends
- Future directions
```

### Batch Processing

Execute multiple prompts:

```
Tool: batch_prompts
Arguments:
{
  "prompts": [
    {
      "prompt": "First task...",
      "temperature": 0.7
    },
    {
      "prompt": "Second task...",
      "temperature": 0.8
    }
  ],
  "combineResults": true
}
```

### Health Check

Verify LM Studio connection:

```
Tool: health_check
```

## Environment Variables

- `LM_STUDIO_URL`: LM Studio server URL (default: http://localhost:1234)

## Use Cases

1. **Code Generation**: Offload routine code generation tasks
2. **Document Analysis**: Process large documents locally
3. **Data Processing**: Transform and analyse data without API limits
4. **Creative Writing**: Generate content with unlimited tokens
5. **Research**: Deep-dive into topics with extended context

## Advantages

- **No API Costs**: Use local models without token limits
- **Privacy**: All processing happens locally
- **Context Preservation**: Save Claude's context for strategic decisions
- **Full Control**: You decide exactly what prompts to run
- **Simplicity**: No complex configuration or preset libraries

## Troubleshooting

1. **Connection Failed**: Ensure LM Studio server is enabled
2. **No Models Found**: Load a model in LM Studio
3. **Timeout**: Increase timeout for large prompts (default: 2 minutes)

## License

MIT
