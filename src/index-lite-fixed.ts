/**
 * Houtini LM Lite - Streamlined Custom Prompt MCP Server
 * Enhanced with Dynamic Token Allocation from original Houtini LM
 * Focus: User-controlled prompt execution with intelligent token management
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { LMStudioClient } from '@lmstudio/sdk';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// ES module __dirname equivalent
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Configuration with dynamic token support
const config = {
  lmStudioUrl: process.env.LM_STUDIO_URL || 'ws://localhost:1234',
  defaultTemperature: 0.7,
  defaultMaxTokens: 4096,
  timeout: 120000, // 2 minutes
  // Dynamic token allocation settings (from original Houtini LM)
  contextUsageRatio: 0.8, // Use 80% of context window (safety margin)
  minOutputTokens: 1000,   // Minimum tokens reserved for output
  tokenEstimateRatio: 3     // Conservative: 3 chars ≈ 1 token
};

/**
 * Dynamic Token Calculator
 * Inspired by original Houtini LM's sophisticated token management
 */
class DynamicTokenCalculator {
  private modelContextLength: number = 128000; // Default to Qwen3's context
  private modelIdentifier: string = '';
  
  /**
   * Update model context information
   */
  updateModelInfo(identifier: string, contextLength?: number) {
    this.modelIdentifier = identifier;
    
    // Known model context sizes (expandable)
    const knownContextSizes: Record<string, number> = {
      'qwen3': 128000,
      'qwen.qwen3': 128000,
      'llama': 32000,
      'codellama': 16000,
      'deepseek': 32000,
      'meta-llama': 8000,
      // Add more as needed
    };
    
    // Try to detect context size from model name
    if (contextLength) {
      this.modelContextLength = contextLength;
    } else {
      // Check if model identifier contains known model names
      for (const [modelKey, contextSize] of Object.entries(knownContextSizes)) {
        if (identifier.toLowerCase().includes(modelKey)) {
          this.modelContextLength = contextSize;
          break;
        }
      }
    }
  }
  
  /**
   * Estimate token count conservatively
   */
  estimateTokens(text: string): number {
    if (!text) return 0;
    return Math.ceil(text.length / config.tokenEstimateRatio);
  }
  
  /**
   * Calculate optimal token allocation for a prompt
   */
  calculateOptimalTokens(
    prompt: string,
    context?: string,
    systemPrompt?: string,
    options: {
      minTokens?: number;
      forceTokens?: number;
    } = {}
  ): number {
    const { minTokens = config.minOutputTokens, forceTokens } = options;
    
    // If user explicitly set maxTokens, respect it
    if (forceTokens && forceTokens > 0) {
      return forceTokens;
    }
    
    // Calculate input tokens
    const promptTokens = this.estimateTokens(prompt);
    const contextTokens = context ? this.estimateTokens(context) : 0;
    const systemTokens = systemPrompt ? this.estimateTokens(systemPrompt) : 0;
    const totalInputTokens = promptTokens + contextTokens + systemTokens;
    
    // Calculate available context (80% of total for safety)
    const usableContext = Math.floor(this.modelContextLength * config.contextUsageRatio);
    
    // Calculate optimal output tokens
    const availableForOutput = usableContext - totalInputTokens;
    const optimalTokens = Math.max(minTokens, availableForOutput);
    
    // Removed console.error statements that interfere with JSON-RPC
    
    return optimalTokens;
  }
  
  /**
   * Check if content needs chunking
   */
  needsChunking(
    prompt: string,
    context?: string,
    systemPrompt?: string
  ): boolean {
    const totalInputTokens = 
      this.estimateTokens(prompt) + 
      (context ? this.estimateTokens(context) : 0) +
      (systemPrompt ? this.estimateTokens(systemPrompt) : 0);
    
    const usableContext = Math.floor(this.modelContextLength * config.contextUsageRatio);
    
    // Need chunking if input + minimum output exceeds usable context
    return (totalInputTokens + config.minOutputTokens) > usableContext;
  }
  
  /**
   * Get diagnostic info for debugging (without console output)
   */
  getDiagnostics(): any {
    return {
      model: this.modelIdentifier,
      contextWindow: this.modelContextLength,
      usableContext: Math.floor(this.modelContextLength * config.contextUsageRatio),
      contextUsageRatio: config.contextUsageRatio
    };
  }
}

class HoutiniLMLite {
  private server: Server;
  private lmStudioClient: LMStudioClient;
  private tokenCalculator: DynamicTokenCalculator;
  
  constructor() {
    this.server = new Server(
      {
        name: 'houtini-lm-lite',
        version: '2.1.0',
        description: 'Streamlined LM Studio offloading with dynamic token allocation - inspired by original Houtini LM',
      },
      {
        capabilities: {
          tools: {
            description: 'Custom prompt execution with intelligent token management'
          }
        },
      }
    );
    
    this.lmStudioClient = new LMStudioClient({
      baseUrl: config.lmStudioUrl,
    });
    
    this.tokenCalculator = new DynamicTokenCalculator();
    
    this.setupHandlers();
    
    // Error handling - removed console.error
    this.server.onerror = (error) => {
      // Silent error handling for MCP compliance
    };
    
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }
  
  private setupHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'custom_prompt',
          description: 'Execute a custom prompt with dynamic token allocation based on your loaded model',
          inputSchema: {
            type: 'object',
            properties: {
              prompt: {
                type: 'string',
                description: 'Your complete prompt to send to the local LLM'
              },
              context: {
                type: 'string',
                description: 'Optional context or background information'
              },
              temperature: {
                type: 'number',
                description: 'Temperature for generation (0-1, default 0.7)',
                minimum: 0,
                maximum: 1
              },
              maxTokens: {
                type: 'number',
                description: 'Maximum tokens (optional - uses dynamic allocation if not set)',
                minimum: 1
              },
              systemPrompt: {
                type: 'string',
                description: 'Optional system prompt to guide the model'
              }
            },
            required: ['prompt']
          }
        },
        {
          name: 'execute_file_prompt',
          description: 'Execute a prompt from a file with variable substitution and dynamic tokens',
          inputSchema: {
            type: 'object',
            properties: {
              filePath: {
                type: 'string',
                description: 'Path to the prompt file'
              },
              variables: {
                type: 'object',
                description: 'Variables to substitute in the prompt (e.g., {name: "value"})'
              },
              temperature: {
                type: 'number',
                description: 'Temperature for generation (0-1, default 0.7)',
                minimum: 0,
                maximum: 1
              },
              maxTokens: {
                type: 'number',
                description: 'Maximum tokens (optional - uses dynamic allocation if not set)',
                minimum: 1
              }
            },
            required: ['filePath']
          }
        },
        {
          name: 'batch_prompts',
          description: 'Execute multiple prompts with intelligent token distribution',
          inputSchema: {
            type: 'object',
            properties: {
              prompts: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    prompt: { type: 'string' },
                    context: { type: 'string' },
                    temperature: { type: 'number' },
                    maxTokens: { type: 'number' }
                  },
                  required: ['prompt']
                },
                description: 'Array of prompts to execute'
              },
              combineResults: {
                type: 'boolean',
                description: 'Whether to combine all results into one response (default false)'
              }
            },
            required: ['prompts']
          }
        },
        {
          name: 'health_check',
          description: 'Check LM Studio connection and model capabilities',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        }
      ]
    }));

    // Handle tool execution
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      
      try {
        switch (name) {
          case 'custom_prompt':
            return await this.executeCustomPrompt(args);
            
          case 'execute_file_prompt':
            return await this.executeFilePrompt(args);
            
          case 'batch_prompts':
            return await this.executeBatchPrompts(args);
            
          case 'health_check':
            return await this.checkHealth();
            
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error: any) {
        return {
          content: [{
            type: 'text',
            text: `Error: ${error.message}`
          }]
        };
      }
    });
  }
  
  /**
   * Initialize model info for token calculator
   */
  private async initializeModelInfo() {
    try {
      const models = await this.lmStudioClient.llm.listLoaded();
      if (models.length > 0) {
        // Update token calculator with model info
        this.tokenCalculator.updateModelInfo(models[0].identifier);
      }
    } catch (error) {
      // Silent fail - will use defaults
    }
  }
  
  /**
   * Execute a custom prompt with dynamic token allocation
   */
  private async executeCustomPrompt(args: any) {
    const {
      prompt,
      context = '',
      temperature = config.defaultTemperature,
      maxTokens,
      systemPrompt = ''
    } = args;
    
    try {
      // Initialize model info if needed
      await this.initializeModelInfo();
      
      // Build the complete prompt
      let fullPrompt = prompt;
      if (context) {
        fullPrompt = `Context: ${context}\n\n${prompt}`;
      }
      
      // Calculate optimal tokens using dynamic allocation
      const finalMaxTokens = this.tokenCalculator.calculateOptimalTokens(
        prompt,
        context,
        systemPrompt,
        { forceTokens: maxTokens }
      );
      
      // Get diagnostic info for the response
      const diagnostics = this.tokenCalculator.getDiagnostics();
      const needsChunking = this.tokenCalculator.needsChunking(prompt, context, systemPrompt);
      
      // Get available models
      const models = await this.lmStudioClient.llm.listLoaded();
      if (models.length === 0) {
        throw new Error('No models loaded in LM Studio. Please load a model first.');
      }
      
      // Use the first loaded model
      const model = models[0];
      
      // Execute the prompt
      const startTime = Date.now();
      const response = await model.complete(fullPrompt, {
        temperature,
        maxTokens: finalMaxTokens
      });
      
      const executionTime = Date.now() - startTime;
      
      // Extract the actual text content from the response
      const responseText = typeof response === 'string' ? response : 
                          (response as any).content || (response as any).text || 
                          JSON.stringify(response);
      
      // Format response with diagnostic info embedded in the text
      const responseWithInfo = `${responseText}

[Token Allocation Info]
Model: ${diagnostics.model}
Context Window: ${diagnostics.contextWindow.toLocaleString()} tokens
Usable Context: ${diagnostics.usableContext.toLocaleString()} tokens
Allocated Output Tokens: ${finalMaxTokens.toLocaleString()}
Input Estimate: ${this.tokenCalculator.estimateTokens(fullPrompt)} tokens
Execution Time: ${executionTime}ms
Temperature: ${temperature}
Needs Chunking: ${needsChunking ? 'Yes - consider breaking into smaller prompts' : 'No'}`;
      
      // Return only the required MCP format
      return {
        content: [{
          type: 'text',
          text: responseWithInfo
        }]
      };
    } catch (error: any) {
      throw new Error(`LM Studio error: ${error.message}`);
    }
  }
  
  /**
   * Execute a prompt from a file with variable substitution
   */
  private async executeFilePrompt(args: any) {
    const {
      filePath,
      variables = {},
      temperature = config.defaultTemperature,
      maxTokens
    } = args;
    
    try {
      // Read the prompt file
      const promptContent = await fs.readFile(filePath, 'utf-8');
      
      // Substitute variables
      let processedPrompt = promptContent;
      for (const [key, value] of Object.entries(variables)) {
        const pattern = new RegExp(`{{\\s*${key}\\s*}}`, 'g');
        processedPrompt = processedPrompt.replace(pattern, String(value));
      }
      
      // Execute the processed prompt with dynamic tokens
      return await this.executeCustomPrompt({
        prompt: processedPrompt,
        temperature,
        maxTokens
      });
    } catch (error: any) {
      if (error.code === 'ENOENT') {
        throw new Error(`Prompt file not found: ${filePath}`);
      }
      throw error;
    }
  }
  
  /**
   * Execute multiple prompts in sequence with dynamic token allocation
   */
  private async executeBatchPrompts(args: any) {
    const { prompts, combineResults = false } = args;
    const results = [];
    
    // Initialize model info once for all prompts
    await this.initializeModelInfo();
    
    for (const [index, promptConfig] of prompts.entries()) {
      try {
        const result = await this.executeCustomPrompt(promptConfig);
        // Extract just the response text, not the diagnostic info for batch
        const responseText = result.content[0].text.split('\n\n[Token Allocation Info]')[0];
        results.push({
          index,
          success: true,
          result: responseText
        });
      } catch (error: any) {
        results.push({
          index,
          success: false,
          error: error.message
        });
      }
    }
    
    if (combineResults) {
      const combinedText = results
        .filter(r => r.success)
        .map(r => `[Prompt ${r.index + 1}]:\n${r.result}`)
        .join('\n\n---\n\n');
      
      const diagnostics = this.tokenCalculator.getDiagnostics();
      const summaryText = `${combinedText}

[Batch Execution Summary]
Total Prompts: ${prompts.length}
Successful: ${results.filter(r => r.success).length}
Failed: ${results.filter(r => !r.success).length}
Model: ${diagnostics.model}
Context Window: ${diagnostics.contextWindow.toLocaleString()} tokens`;
      
      return {
        content: [{
          type: 'text',
          text: summaryText
        }]
      };
    }
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(results, null, 2)
      }]
    };
  }
  
  /**
   * Enhanced health check showing model capabilities
   */
  private async checkHealth() {
    try {
      const models = await this.lmStudioClient.llm.listLoaded();
      
      // Update token calculator with model info
      if (models.length > 0) {
        this.tokenCalculator.updateModelInfo(models[0].identifier);
      }
      
      let healthInfo = `LM Studio is running and connected.
URL: ${config.lmStudioUrl}
Available models: ${models.length}`;

      if (models.length > 0) {
        const modelId = models[0].identifier;
        const diagnostics = this.tokenCalculator.getDiagnostics();
        
        healthInfo += `
Active model: ${modelId}
Context window: ${diagnostics.contextWindow.toLocaleString()} tokens
Usable context (80%): ${diagnostics.usableContext.toLocaleString()} tokens
Dynamic token allocation: Enabled`;
      } else {
        healthInfo += '\nNo models loaded - please load a model in LM Studio';
      }
      
      return {
        content: [{
          type: 'text',
          text: healthInfo
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: 'text',
          text: `LM Studio connection failed: ${error.message}
Please ensure LM Studio is running and the server is enabled at ${config.lmStudioUrl}`
        }]
      };
    }
  }
  
  async start() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    // Removed console.error for MCP compliance
  }
}

// Start the server
const server = new HoutiniLMLite();
server.start().catch((error) => {
  // Silent fail for MCP compliance
  process.exit(1);
});