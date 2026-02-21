# Houtini LM Lite v2.1.0 - Testing Handover

## Current State: Ready for Testing

### System Configuration
- **Working Directory**: `C:\MCP\houtini-lm`
- **MCP Server**: houtini-lm-lite (local version)
- **LM Studio**: Running at `ws://localhost:1234`
- **Loaded Model**: qwen.qwen3-coder-30b-a3b-instruct
- **Model Context**: 128,000 tokens (102,400 usable with 80% safety margin)

### What Was Just Implemented
Successfully enhanced Houtini LM Lite with dynamic token allocation system from the original Houtini LM:
- Automatic token optimization based on input size
- Model-aware context detection
- Conservative 80% context usage with safety margins
- Transparent logging of token allocation decisions

### Claude Configuration Updated
The `claude_desktop_config.json` has been modified to include:
```json
"houtini-lm-lite": {
  "command": "node",
  "args": ["C:\\MCP\\houtini-lm\\dist\\index-lite.js"],
  "env": {
    "LM_STUDIO_URL": "ws://localhost:1234",
    "LLM_MCP_ALLOWED_DIRS": "C:/MCP,C:/dev"
  }
}
```

### Files Created/Modified
1. **Enhanced**: `src/index-lite.ts` - Now includes DynamicTokenCalculator class
2. **Compiled**: `dist/index-lite.js` - Ready to run with dynamic tokens
3. **Documentation**: `DYNAMIC_TOKENS_IMPLEMENTATION.md` - Full implementation details
4. **Backup**: `claude_desktop_config_backup.json` - Original config saved

## Testing Instructions

### Step 1: Restart Claude Desktop
1. Close all Claude instances (check system tray)
2. Wait 5 seconds
3. Start Claude Desktop fresh
4. Start a new conversation

### Step 2: Initial Health Check
Test the connection and verify dynamic tokens are working:
```
Use houtini-lm-lite:health_check
```

Expected output should show:
- LM Studio connected
- Model: qwen.qwen3-coder-30b-a3b-instruct
- Context window: 128,000 tokens
- Usable context: 102,400 tokens
- Dynamic token allocation: Enabled

### Step 3: Test Dynamic Token Allocation

#### Test 1: Small Prompt (Should allocate maximum tokens)
```
Use houtini-lm-lite:custom_prompt with:
- prompt: "Write a simple hello world function in Python"
- Don't specify maxTokens (let it calculate)
```
Check metadata in response - should show ~100,000+ tokens allocated

#### Test 2: Large Context (Should adapt allocation)
```
Use houtini-lm-lite:custom_prompt with:
- prompt: "Analyze this code"
- context: [paste a large code file, 10,000+ chars]
```
Check metadata - tokens should be reduced based on input size

#### Test 3: Manual Override (Should respect user setting)
```
Use houtini-lm-lite:custom_prompt with:
- prompt: "Give me a brief answer"
- maxTokens: 500
```
Should use exactly 500 tokens, not dynamic calculation

#### Test 4: Batch Processing (Should optimize each)
```
Use houtini-lm-lite:batch_prompts with:
- Multiple prompts of varying sizes
- combineResults: true
```
Each prompt should get optimal token allocation

### Step 4: Monitor Token Logs
Watch the Claude Desktop console (if available) for stderr output showing:
```
[Token Allocation] Model: qwen.qwen3-coder-30b-a3b-instruct
[Token Allocation] Context: 128000 → Usable: 102400
[Token Allocation] Input: XXX → Output: YYY
```

## What to Validate

### ✅ Success Criteria
1. Dynamic allocation working (large token counts for small prompts)
2. Automatic scaling (reduced tokens for large inputs)
3. Manual override respected when maxTokens specified
4. No errors or connection issues
5. Faster/better responses due to optimal token usage

### ⚠️ Potential Issues
1. If "houtini-lm-lite" not found → Claude needs restart
2. If connection fails → Check LM Studio is running
3. If tokens seem fixed → Dynamic allocation may not be active
4. If model shows different context → Detection may need tuning

## Key Advantages to Test
With dynamic tokens, you should experience:
1. **Much longer outputs** for simple prompts (up to 100K tokens!)
2. **Automatic optimization** - no manual token tweaking needed
3. **Safety from overflows** - 80% usage prevents context errors
4. **Transparency** - metadata shows exactly what's allocated

## Quick Reference

### Available Tools
- `houtini-lm-lite:custom_prompt` - Execute prompts with dynamic tokens
- `houtini-lm-lite:execute_file_prompt` - File-based prompts with variables
- `houtini-lm-lite:batch_prompts` - Multiple prompts with optimization
- `houtini-lm-lite:health_check` - Verify connection and capabilities

### Token Formula
```
maxTokens = max(1000, (128000 × 0.8) - estimatedInputTokens)
```

### Context Usage
- Total: 128,000 tokens
- Usable: 102,400 tokens (80%)
- Reserved: 25,600 tokens (20% safety)
- Minimum output: 1,000 tokens

## Next Thread Opening
"Hi Claude, I need to test the Houtini LM Lite v2.1.0 with dynamic token allocation. The system should be ready with:
- Working directory: C:\MCP\houtini-lm
- LM Studio running with qwen3-coder-30b model
- Local houtini-lm-lite MCP server configured
- Dynamic token allocation implemented

Can you run a health check first to verify everything is connected?"

---
Ready for testing! Start a new thread after restarting Claude Desktop.
