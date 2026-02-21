# Houtini LM Lite - Dynamic Token Allocation Enhancement

## Version 2.1.0 Release Notes

### Overview
Successfully enhanced Houtini LM Lite with the dynamic token allocation system inspired by the original Houtini LM codebase. This brings intelligent, model-aware token management to the streamlined lite version.

## Key Features Added

### 1. Dynamic Token Calculator
- **Automatic Model Detection**: Recognizes loaded model and adapts to its context window
- **Conservative Token Usage**: Uses 80% of context window for safety margin
- **Intelligent Token Estimation**: 3 characters ≈ 1 token (conservative estimate)

### 2. Token Allocation Formula
```
maxTokens = max(minTokens, (contextLength × 0.80) - estimatedInputTokens)
```

### 3. Model-Specific Optimizations
For your Qwen3 Coder 30B model (128K context):
- **Total Context**: 128,000 tokens
- **Usable Context**: 102,400 tokens (80%)
- **Dynamic Range**: 1,000 to ~100,000 tokens per request

### 4. Smart Features
- **Automatic Chunking Detection**: Warns when content exceeds context
- **Token Transparency**: Logs allocation decisions to stderr for debugging
- **User Override**: Respects manual maxTokens when specified
- **Batch Optimization**: Applies dynamic allocation across multiple prompts

## Usage Examples

### Simple Usage (Dynamic Allocation)
```javascript
// Claude will automatically use optimal tokens
houtini-lm-lite:custom_prompt({
  prompt: "Analyze this code and suggest improvements",
  context: largeCodebase
  // maxTokens calculated automatically based on input size
})
```

### Manual Override
```javascript
// Force specific token count
houtini-lm-lite:custom_prompt({
  prompt: "Brief summary please",
  maxTokens: 500  // Override dynamic allocation
})
```

### Check Allocation
```javascript
// See token calculation details
houtini-lm-lite:health_check()
// Shows: Context window, usable tokens, allocation status
```

## Technical Implementation

### Known Model Context Sizes
- Qwen3 models: 128,000 tokens
- LLaMA models: 32,000 tokens
- CodeLlama: 16,000 tokens
- DeepSeek: 32,000 tokens
- Meta-LLaMA: 8,000 tokens

### Safety Margins
- Context Usage: 80% (leaving 20% buffer)
- Minimum Output: 1,000 tokens reserved
- Token Estimation: Conservative 3:1 char ratio

## Benefits

1. **No Wasted Context**: Always uses maximum available tokens
2. **Model Aware**: Automatically adapts to different models
3. **Prevents Overflows**: Built-in safety margins
4. **Transparent**: Logs allocation decisions for debugging
5. **Flexible**: Allows manual override when needed

## Migration from v2.0.0 to v2.1.0

No breaking changes. The enhancement is backward compatible:
- Existing prompts work unchanged
- Dynamic allocation is automatic
- Manual maxTokens still respected
- Added metadata in responses shows token usage

## Files Modified

1. `src/index-lite.ts` - Enhanced with DynamicTokenCalculator class
2. `dist/index-lite.js` - Compiled version with dynamic tokens
3. Created backup: `src/index-lite-enhanced.ts` for reference

## Next Steps

After restarting Claude Desktop:
1. Test with large prompts to see dynamic allocation
2. Monitor token usage in metadata responses
3. Use health_check to verify model detection

## Performance Impact

With Qwen3 30B's 128K context:
- Small prompts (<1K tokens): Allocates ~100K for output
- Medium prompts (10K tokens): Allocates ~90K for output  
- Large prompts (50K tokens): Allocates ~50K for output
- Massive prompts (>100K tokens): Warns about chunking need

This ensures you always get the maximum possible output while staying within safe limits.
