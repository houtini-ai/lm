/**
 * Houtini LM Lite - Streamlined Custom Prompt MCP Server
 * Focus: User-controlled prompt execution with LM Studio offloading
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

// Simple configuration
const config = {
  lmStudioUrl: process.env.LM_STUDIO_URL || 'http://localhost:1234',
  defaultTemperature: 0.7,
  defaultMaxTokens: 4096,
  timeout: 120000 // 2 minutes
};

class HoutiniLMLite {
  private server: Server;
  private lmStudioClient: LMStudioClient;
  
  constructor() {
    this.server = new Server(
      {
        name: 'houtini-lm-lite',
        version: '2.0.0',
        description: 'Streamlined LM Studio offloading - complete user control over prompts',
      },
      {
        capabilities: {
          tools: {
            description: 'Custom prompt execution with full user control'
          }
        },
      }
    );
    
    this.lmStudioClient = new LMStudioClient({
      baseUrl: config.lmStudioUrl,
    });
    
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
          description: 'Execute a custom prompt with LM Studio - complete control over content and parameters',
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
                description: 'Maximum tokens to generate (default 4096)',
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
          description: 'Execute a prompt from a file with optional variable substitution',
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
                description: 'Maximum tokens to generate (default 4096)',
                minimum: 1
              }
            },
            required: ['filePath']
          }
        },
        {
          name: 'batch_prompts',
          description: 'Execute multiple prompts in sequence',
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
          description: 'Check if LM Studio is running and responding',
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
   * Execute a custom prompt with full user control
   */
  private async executeCustomPrompt(args: any) {
    const {
      prompt,
      context = '',
      temperature = config.defaultTemperature,
      maxTokens = config.defaultMaxTokens,
      systemPrompt = ''
    } = args;
    
    try {
      // Build the complete prompt
      let fullPrompt = prompt;
      if (context) {
        fullPrompt = `Context: ${context}\n\n${prompt}`;
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
        maxTokens
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
          maxTokens
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
      maxTokens = config.defaultMaxTokens
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
   * Execute multiple prompts in sequence
   */
  private async executeBatchPrompts(args: any) {
    const { prompts, combineResults = false } = args;
    const results = [];
    
    for (const [index, promptConfig] of prompts.entries()) {
      try {
        const result = await this.executeCustomPrompt(promptConfig);
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
          failed: results.filter(r => !r.success).length
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
   * Check LM Studio health
   */
  private async checkHealth() {
    try {
      const models = await this.lmStudioClient.llm.listLoaded();
      
      return {
        content: [{
          type: 'text',
          text: `LM Studio is running and connected.
URL: ${config.lmStudioUrl}
Available models: ${models.length}
${models.length > 0 ? `Active model: ${models[0].identifier}` : 'No models loaded - please load a model in LM Studio'}`
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
    console.error('Houtini LM Lite server started');
  }
}

// Start the server
const server = new HoutiniLMLite();
server.start().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
