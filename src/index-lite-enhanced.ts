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
  // Dynamic token allocation settings
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
    
    // Known model context sizes (can be expanded)
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
    
    // Log calculation for transparency
    console.error(`[Token Allocation] Model: ${this.modelIdentifier}`);
    console.error(`[Token Allocation] Context Window: ${this.modelContextLength}`);
    console.error(`[Token Allocation] Usable Context (80%): ${usableContext}`);
    console.error(`[Token Allocation] Input Tokens: ${totalInputTokens}`);
    console.error(`[Token Allocation] Allocated Output Tokens: ${optimalTokens}`);
    
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
   * Calculate chunk size for large content
   */
  calculateChunkSize(): number {
    const usableContext = Math.floor(this.modelContextLength * config.contextUsageRatio);
    // Reserve space for system prompt and output
    return Math.floor(usableContext * 0.5); // Use 50% for data chunks
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
        description: 'Streamlined LM Studio offloading with dynamic token allocation',
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
    
    // Error handling
    this.server.onerror = (error) => {
      console.error('[Server Error]:', error);
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
              },
              useDynamicTokens: {
                type: 'boolean',
                description: 'Enable dynamic token allocation (default true)'
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
              },
              useDynamicTokens: {
                type: 'boolean',
                description: 'Enable dynamic token allocation (default true)'
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
              },
              useDynamicTokens: {
                type: 'boolean',
                description: 'Enable dynamic token allocation for each prompt (default true)'
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
            properties: {
              detailed: {
                type: 'boolean',
                description: 'Include detailed model information (default false)'
              }
            }
          }
        },
        {
          name: 'get_token_info',
          description: 'Get information about current token allocation settings',
          inputSchema: {
            type: 'object',
            properties: {
              prompt: {
                type: 'string',
                description: 'Optional prompt to calculate tokens for'
              },
              context: {
                type: 'string',
                description: 'Optional context to include in calculation'
              }
            }
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
            return await this.checkHealth(args);
            
          case 'get_token_info':
            return await this.getTokenInfo(args);
            
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
      systemPrompt = '',
      useDynamicTokens = true
    } = args;
    
    try {
      // Initialize model info if needed
      await this.initializeModelInfo();
      
      // Build the complete prompt
      let fullPrompt = prompt;
      if (context) {
        fullPrompt = `Context: ${context}\n\n${prompt}`;
      }
      
      // Calculate optimal tokens if dynamic allocation is enabled
      const finalMaxTokens = useDynamicTokens 
        ? this.tokenCalculator.calculateOptimalTokens(
            prompt,
            context,
            systemPrompt,
            { forceTokens: maxTokens }
          )
        : (maxTokens || config.defaultMaxTokens);
      
      // Check if content needs chunking
      if (useDynamicTokens && this.tokenCalculator.needsChunking(prompt, context, systemPrompt)) {
        console.error('[Token Allocation] Content exceeds context - consider chunking');
      }
      
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
      
      return {
        content: [{
          type: 'text',
          text: response
        }],
        metadata: {
          model: models[0].identifier,
          executionTimeMs: executionTime,
          temperature,
          maxTokens: finalMaxTokens,
          dynamicTokensUsed: useDynamicTokens,
          inputTokensEstimate: this.tokenCalculator.estimateTokens(fullPrompt),
          outputTokensAllocated: finalMaxTokens
        }
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
      maxTokens,
      useDynamicTokens = true
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
      
      // Execute the processed prompt
      return await this.executeCustomPrompt({
        prompt: processedPrompt,
        temperature,
        maxTokens,
        useDynamicTokens
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
    const { prompts, combineResults = false, useDynamicTokens = true } = args;
    const results = [];
    
    // Initialize model info once for all prompts
    await this.initializeModelInfo();
    
    for (const [index, promptConfig] of prompts.entries()) {
      try {
        const result = await this.executeCustomPrompt({
          ...promptConfig,
          useDynamicTokens
        });
        results.push({
          index,
          success: true,
          result: result.content[0].text,
          metadata: result.metadata
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
      
      return {
        content: [{
          type: 'text',
          text: combinedText
        }],
        metadata: {
          totalPrompts: prompts.length,
          successful: results.filter(r => r.success).length,
          failed: results.filter(r => !r.success).length,
          dynamicTokensUsed: useDynamicTokens
        }
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
   * Enhanced health check with model capabilities
   */
  private async checkHealth(args: any = {}) {
    const { detailed = false } = args;
    
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
        healthInfo += `\nActive model: ${modelId}`;
        
        if (detailed) {
          // Try to get model context info
          const contextEstimate = this.tokenCalculator['modelContextLength'];
          healthInfo += `\nEstimated context window: ${contextEstimate.toLocaleString()} tokens`;
          healthInfo += `\nUsable context (80%): ${Math.floor(contextEstimate * 0.8).toLocaleString()} tokens`;
          healthInfo += `\nToken estimation ratio: 3 chars ≈ 1 token`;
          healthInfo += `\nDynamic token allocation: Enabled`;
        }
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
  
  /**
   * Get token allocation information
   */
  private async getTokenInfo(args: any) {
    const { prompt = '', context = '' } = args;
    
    try {
      await this.initializeModelInfo();
      
      const inputTokens = this.tokenCalculator.estimateTokens(prompt + context);
      const optimalOutput = this.tokenCalculator.calculateOptimalTokens(prompt, context);
      const needsChunking = this.tokenCalculator.needsChunking(prompt, context);
      const chunkSize = this.tokenCalculator.calculateChunkSize();
      
      const info = {
        modelContextWindow: this.tokenCalculator['modelContextLength'],
        usableContext: Math.floor(this.tokenCalculator['modelContextLength'] * config.contextUsageRatio),
        inputTokensEstimate: inputTokens,
        optimalOutputTokens: optimalOutput,
        totalTokensWillUse: inputTokens + optimalOutput,
        needsChunking,
        recommendedChunkSize: needsChunking ? chunkSize : null,
        settings: {
          contextUsageRatio: config.contextUsageRatio,
          minOutputTokens: config.minOutputTokens,
          tokenEstimateRatio: config.tokenEstimateRatio
        }
      };
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(info, null, 2)
        }]
      };
    } catch (error: any) {
      throw new Error(`Token info error: ${error.message}`);
    }
  }
  
  async start() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Houtini LM Lite Enhanced server started (v2.1.0 with dynamic tokens)');
  }
}

// Start the server
const server = new HoutiniLMLite();
server.start().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
