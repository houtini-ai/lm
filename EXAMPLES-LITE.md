# Houtini LM Lite - Examples

## Example Prompt Files

Create these files in a `prompts` directory to use with the `execute_file_prompt` tool.

### 1. Code Review Template (`prompts/code-review.txt`)

```
Please review the following {{language}} code:

{{code}}

Focus on:
1. Code quality and readability
2. Potential bugs or edge cases
3. Performance considerations
4. Security concerns
5. Best practices for {{language}}

Provide specific suggestions for improvement with code examples where relevant.
```

### 2. Document Summary (`prompts/summarise.txt`)

```
Summarise the following {{document_type}} in {{style}} style:

{{content}}

Key requirements:
- Length: {{length}} words
- Focus areas: {{focus}}
- Target audience: {{audience}}
```

### 3. Data Analysis (`prompts/analyse-data.txt`)

```
Analyse the following dataset:

{{data}}

Provide insights on:
- Key patterns and trends
- Statistical summary
- Anomalies or outliers
- Recommendations based on findings
- Visualisation suggestions

Output format: {{format}}
```

## Usage Examples

### Example 1: Code Review

```javascript
// In Claude
await use_tool('execute_file_prompt', {
  filePath: 'C:/prompts/code-review.txt',
  variables: {
    language: 'Python',
    code: `
def calculate_average(numbers):
    total = 0
    for num in numbers:
        total += num
    return total / len(numbers)
    `
  },
  temperature: 0.7
});
```

### Example 2: Batch Analysis

```javascript
await use_tool('batch_prompts', {
  prompts: [
    {
      prompt: "Generate 5 test cases for a login function",
      temperature: 0.8
    },
    {
      prompt: "Create documentation for the test cases",
      context: "Previous response contains the test cases",
      temperature: 0.6
    },
    {
      prompt: "Write the implementation code for the test cases",
      temperature: 0.7
    }
  ],
  combineResults: true
});
```

### Example 3: Research Task

```javascript
await use_tool('custom_prompt', {
  prompt: "Research and explain quantum computing",
  context: "Focus on practical applications and current limitations",
  systemPrompt: "You are a technology researcher writing for a technical audience",
  temperature: 0.7,
  maxTokens: 8192
});
```

## Workflow Patterns

### 1. Iterative Development
```
1. Generate initial code with custom_prompt
2. Review with execute_file_prompt using code-review template
3. Refine based on feedback
4. Generate tests with batch_prompts
```

### 2. Document Processing
```
1. Load document content
2. Summarise with custom prompt
3. Extract key points with different temperature
4. Generate action items
```

### 3. Data Analysis Pipeline
```
1. Load data
2. Statistical analysis (temperature: 0.3)
3. Pattern recognition (temperature: 0.7)
4. Generate insights (temperature: 0.8)
5. Create recommendations (temperature: 0.6)
```

## Tips

1. **Temperature Settings**:
   - 0.3-0.5: Factual, analytical tasks
   - 0.6-0.7: Balanced creativity and accuracy
   - 0.8-1.0: Creative writing, brainstorming

2. **Token Management**:
   - Start with smaller maxTokens for testing
   - Increase for comprehensive analysis
   - No hard limits - use what you need

3. **Context Usage**:
   - Provide clear context for better results
   - Reference previous outputs in batch processing
   - Use system prompts to set tone and style

4. **File Organisation**:
   - Keep prompts in version control
   - Use meaningful variable names
   - Document your prompt templates
