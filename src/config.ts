/**
 * Configuration for Houtini LM MCP Server v1.0
 * Modern plugin architecture - prompts are handled by individual plugins
 */

import { Config } from './types.js';

export const config: Config = {
  lmStudioUrl: process.env.LM_STUDIO_URL || 'ws://localhost:1234',
  modelName: process.env.LM_STUDIO_MODEL || 'auto',
  temperature: 0.1,
  // maxTokens removed - now calculated dynamically by TokenCalculator
  topP: 0.95,
  timeout: 300000, // Increased to 5 minutes for complex analysis and large projects
  maxFileSize: 200 * 1024 * 1024,  // 200MB limit
  supportedFileTypes: [
    '.csv', '.json', '.txt', '.js', '.ts', '.py', '.md', '.log', 
    '.jsx', '.tsx', '.java', '.c', '.cpp', '.rs', '.go', '.php', 
    '.rb', '.swift', '.html', '.css', '.scss', '.less', '.xml', 
    '.yml', '.yaml', '.toml', '.ini', '.conf', '.sh', '.bat'
  ],
  
  // Security configuration
  security: {
    enableSanitisation: true,
    enableInjectionDetection: true,
    enableOutputEncoding: false, // FIXED: Prevents double JSON escaping
    injectionThreshold: 0.5, // 0-1 scale for detection sensitivity
    allowedDirectories: process.env.LLM_MCP_ALLOWED_DIRS?.split(',') || ['C:\\MCP', 'C:\\DEV'],
    maxInputSize: {
      'file-path': 1000,
      'code': 100000,
      'general': 50000,
      'prompt': 20000
    }
  }
};

/**
 * Default LM Studio configuration
 */
export const lmStudioConfig = {
  baseUrl: config.lmStudioUrl,
  timeout: config.timeout
};

/**
 * File processing limits
 */
export const fileProcessingLimits = {
  maxFileSize: config.maxFileSize,
  supportedTypes: config.supportedFileTypes,
  chunkSize: 50 * 1024 * 1024, // 50MB chunks for large files
  parallelProcessingThreshold: 10 * 1024 * 1024 // 10MB threshold for parallel processing
};

/**
 * Model parameters for different operation types
 * maxTokens now calculated dynamically by TokenCalculator based on context window
 */
export const modelParameters = {
  analysis: {
    temperature: 0.1,
    topP: 0.95
    // maxTokens removed - calculated dynamically
  },
  generation: {
    temperature: 0.3,
    topP: 0.9
    // maxTokens removed - calculated dynamically
  },
  creative: {
    temperature: 0.7,
    topP: 0.9
    // maxTokens removed - calculated dynamically
  }
};
