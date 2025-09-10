/**
 * WordPress Plugin Readiness Analyzer
 * 
 * Comprehensive WordPress plugin readiness check for security, best practices, and WordPress.org submission
 * Analyzes plugin structure, security vulnerabilities, database operations, and coding standards
 */

import { BasePlugin } from '../../plugins/base-plugin.js';
import { IPromptPlugin } from '../shared/types.js';
import { ThreeStagePromptManager } from '../../core/ThreeStagePromptManager.js';
import { PromptStages } from '../../types/prompt-stages.js';
import { withSecurity } from '../../security/integration-helpers.js';
import { readFileContent } from '../shared/helpers.js';
import { 
  ModelSetup, 
  TokenCalculator,
  ResponseProcessor, 
  ParameterValidator, 
  ErrorHandler,
  MultiFileAnalysis
} from '../../utils/plugin-utilities.js';
import { getAnalysisCache } from '../../cache/index.js';

// Common Node.js modules
import { basename, dirname, extname, join, relative } from 'path';
import { readFile, stat, readdir } from 'fs/promises';

export class WordPressPluginReadiness extends BasePlugin implements IPromptPlugin {
  name = 'wordpress_plugin_readiness';
  category = 'analyze' as const;
  description = 'Comprehensive WordPress plugin readiness check for security, best practices, and WordPress.org submission';
  
  parameters = {
    // Primary parameter - WordPress plugin directory
    projectPath: {
      type: 'string' as const,
      description: 'Path to WordPress plugin root directory',
      required: true
    },
    
    // Analysis configuration
    analysisDepth: {
      type: 'string' as const,
      description: 'Level of analysis detail',
      enum: ['basic', 'detailed', 'comprehensive'],
      default: 'comprehensive',
      required: false
    },
    includeSteps: {
      type: 'array' as const,
      description: 'Specific analysis steps to include',
      required: false,
      default: ['structure', 'security', 'database', 'quality', 'standards', 'performance'],
      items: { type: 'string' as const }
    },
    
    // WordPress configuration
    wpVersion: {
      type: 'string' as const,
      description: 'Target WordPress version for compatibility',
      required: false,
      default: '6.4'
    },
    phpVersion: {
      type: 'string' as const,
      description: 'Target PHP version for compatibility',
      required: false,
      default: '8.0'
    },
    
    // File analysis limits
    maxDepth: {
      type: 'number' as const,
      description: 'Maximum directory depth for file discovery (1-5)',
      required: false,
      default: 3
    },
    maxFiles: {
      type: 'number' as const,
      description: 'Maximum number of PHP files to analyze',
      required: false,
      default: 50
    }
  };

  private analysisCache = getAnalysisCache();
  private multiFileAnalysis = new MultiFileAnalysis();

  constructor() {
    super();
  }

  async execute(params: any, llmClient: any) {
    return await withSecurity(this, params, llmClient, async (secureParams) => {
      try {
        // 1. Validate parameters
        ParameterValidator.validateProjectPath(secureParams);
        ParameterValidator.validateDepth(secureParams);
        ParameterValidator.validateEnum(secureParams, 'analysisDepth', ['basic', 'detailed', 'comprehensive']);
        
        // 2. Setup model
        const { model, contextLength } = await ModelSetup.getReadyModel(llmClient);
        
        // 3. Discover PHP files in the plugin
        const phpFiles = await this.discoverPHPFiles(
          secureParams.projectPath,
          secureParams.maxDepth,
          secureParams.maxFiles
        );
        
        // 4. Analyze the plugin structure
        const analysisResult = await this.performPluginAnalysis(
          phpFiles,
          secureParams,
          model,
          contextLength
        );
        
        // 5. Generate comprehensive prompt
        const promptStages = this.getPromptStages({
          ...secureParams,
          analysisResult,
          fileCount: phpFiles.length
        });
        
        // 6. Execute with chunking (always needed for comprehensive analysis)
        const promptManager = new ThreeStagePromptManager();
        const chunkSize = TokenCalculator.calculateOptimalChunkSize(promptStages, contextLength);
        const dataChunks = promptManager.chunkDataPayload(promptStages.dataPayload, chunkSize);
        const conversation = promptManager.createChunkedConversation(promptStages, dataChunks);
        const messages = [
          conversation.systemMessage,
          ...conversation.dataMessages,
          conversation.analysisMessage
        ];
        
        return await ResponseProcessor.executeChunked(
          messages,
          model,
          contextLength,
          'wordpress_plugin_readiness',
          'multifile'
        );
        
      } catch (error: any) {
        return ErrorHandler.createExecutionError('wordpress_plugin_readiness', error);
      }
    });
  }

  /**
   * Generate prompt stages for WordPress plugin analysis
   */
  getPromptStages(params: any): PromptStages {
    const { analysisResult, analysisDepth, includeSteps, wpVersion, phpVersion, fileCount } = params;
    
    const systemAndContext = `You are a WordPress security and best practices expert conducting a comprehensive plugin readiness assessment.

Analysis Context:
- WordPress Version: ${wpVersion}
- PHP Version: ${phpVersion}
- Analysis Depth: ${analysisDepth}
- Files Analyzed: ${fileCount}
- Analysis Steps: ${includeSteps?.join(', ') || 'all'}

Your expertise includes:
- WordPress security best practices and OWASP compliance
- WordPress coding standards and guidelines
- WordPress.org plugin submission requirements
- Performance optimization for WordPress plugins
- Database security and optimization
- Plugin architecture and organization

CRITICAL SECURITY CHECKS:

1. INPUT VALIDATION & SANITIZATION:
- Direct use of $_GET, $_POST, $_REQUEST without sanitization
- Missing sanitize_text_field(), sanitize_email(), sanitize_url()
- Missing esc_html(), esc_attr(), esc_url() for output

2. SQL INJECTION PREVENTION:
- Database queries without $wpdb->prepare()
- String concatenation in SQL queries
- Unsafe use of $wpdb->query() with user input

3. NONCE VERIFICATION:
- Forms without wp_nonce_field()
- AJAX without check_ajax_referer()
- Admin actions without wp_verify_nonce()

4. CAPABILITY CHECKS:
- Admin functions without current_user_can()
- Direct role checks instead of capability checks
- Missing permission validation

5. FILE OPERATIONS:
- Unsafe file uploads without wp_handle_upload()
- Direct file system operations without WP_Filesystem
- Path traversal vulnerabilities

6. XSS PREVENTION:
- Unescaped output in HTML context
- JavaScript variables without wp_json_encode()
- Missing wp_kses() for rich content

Your task is to provide a comprehensive readiness assessment for WordPress.org submission.`;

    const dataPayload = `WordPress Plugin Analysis Results:

${JSON.stringify(analysisResult, null, 2)}`;

    const outputInstructions = `Provide a comprehensive WordPress plugin readiness report with the following sections:

**Executive Summary:**
Provide an overall readiness score (0-100) and a clear verdict on whether the plugin is ready for WordPress.org submission. Highlight the most critical issues that must be addressed.

**Structure Analysis:**
- Assess the plugin file and directory structure
- Identify missing essential files (readme.txt, license, etc.)
- Flag unnecessary files that shouldn't be in production
- Evaluate directory organization best practices

**Security Assessment:**
For each security vulnerability found, provide:
- **Vulnerability Type**: SQL injection, XSS, nonce missing, capability check, etc.
- **Severity Level**: Critical, High, Medium, or Low
- **Affected Files**: Specific files and approximate line numbers
- **Security Impact**: What could happen if exploited
- **Remediation**: Exact code fix with WordPress functions to use
- **Confidence Score**: How certain you are about this finding

**Database Operations:**
- Identify all database queries and their safety status
- Flag unprepared queries vulnerable to SQL injection
- Check for proper use of $wpdb->prefix
- Identify inefficient queries and N+1 problems
- Suggest query optimizations

**WordPress Standards Compliance:**
- **Coding Standards**: Adherence to WordPress PHP coding standards
- **Naming Conventions**: Function names, variable names, class names
- **Text Domain**: Consistency in internationalization
- **Deprecated Functions**: Usage of deprecated WordPress functions
- **API Usage**: Proper use of WordPress APIs and hooks

**Performance Analysis:**
- Scripts and styles loading inefficiently
- Database queries in loops
- Missing caching for expensive operations
- Resource-intensive operations on page load
- Suggest specific performance improvements

**Documentation & Metadata:**
- **Plugin Headers**: Completeness and accuracy
- **Readme.txt**: Presence and compliance with WordPress.org format
- **License**: Proper GPL-compatible license declaration
- **Inline Documentation**: PHPDoc blocks and code comments

**WordPress.org Submission Checklist:**
Provide a clear pass/fail for each requirement:
- ✅/❌ Valid plugin structure
- ✅/❌ No critical security vulnerabilities
- ✅/❌ Proper database operations
- ✅/❌ WordPress coding standards compliance
- ✅/❌ Complete readme.txt file
- ✅/❌ GPL-compatible license
- ✅/❌ No use of deprecated functions
- ✅/❌ Proper internationalization

**Priority Action Items:**
List the top 5-10 most important fixes needed, ordered by priority:
1. [Critical Security]: Specific issue and fix
2. [Required for Submission]: Missing requirement
3. [High Priority]: Important improvement
(Continue as needed)

**Recommendations for Improvement:**
Beyond the minimum requirements, suggest enhancements that would make this a high-quality plugin:
- Architecture improvements
- Code quality enhancements
- User experience optimizations
- Additional security hardening

Focus on being specific, actionable, and providing exact WordPress functions and patterns to use. Every finding should include a concrete solution that developers can implement immediately.`;

    return { systemAndContext, dataPayload, outputInstructions };
  }

  /**
   * Discover PHP files in the WordPress plugin
   */
  private async discoverPHPFiles(
    projectPath: string,
    maxDepth: number,
    maxFiles: number
  ): Promise<string[]> {
    const phpFiles: string[] = [];
    
    const scanDirectory = async (dir: string, depth: number = 0) => {
      if (depth > maxDepth || phpFiles.length >= maxFiles) return;
      
      try {
        const items = await readdir(dir);
        
        for (const item of items) {
          if (phpFiles.length >= maxFiles) break;
          
          const fullPath = join(dir, item);
          const itemStat = await stat(fullPath);
          
          if (itemStat.isDirectory()) {
            // Skip common non-code directories
            if (!item.startsWith('.') && 
                item !== 'node_modules' && 
                item !== 'vendor' &&
                item !== 'tests' &&
                item !== '.git') {
              await scanDirectory(fullPath, depth + 1);
            }
          } else if (item.endsWith('.php')) {
            phpFiles.push(fullPath);
          }
        }
      } catch (error) {
        // Continue scanning even if one directory fails
      }
    };
    
    await scanDirectory(projectPath);
    
    // Also check for critical WordPress files in root
    const criticalFiles = ['readme.txt', 'license.txt', 'LICENSE'];
    for (const file of criticalFiles) {
      const fullPath = join(projectPath, file);
      try {
        await stat(fullPath);
        phpFiles.push(fullPath); // Include these for completeness check
      } catch {
        // File doesn't exist, will be flagged in analysis
      }
    }
    
    return phpFiles;
  }

  /**
   * Perform comprehensive plugin analysis
   */
  private async performPluginAnalysis(
    files: string[],
    params: any,
    model: any,
    contextLength: number
  ): Promise<any> {
    const analysisResults: any = {
      structure: {
        totalFiles: files.length,
        phpFiles: files.filter(f => f.endsWith('.php')).length,
        hasReadme: files.some(f => basename(f).toLowerCase() === 'readme.txt'),
        hasLicense: files.some(f => basename(f).toLowerCase().includes('license')),
        directories: this.extractDirectoryStructure(files, params.projectPath)
      },
      files: [],
      security: {
        vulnerabilities: [],
        summary: {}
      },
      database: {
        queries: [],
        summary: {}
      },
      standards: {
        issues: [],
        summary: {}
      }
    };
    
    // Analyze each PHP file
    for (const file of files.filter(f => f.endsWith('.php'))) {
      try {
        const content = await readFile(file, 'utf-8');
        const fileAnalysis = await this.analyzeFile(file, content, params);
        analysisResults.files.push(fileAnalysis);
        
        // Aggregate security issues
        if (fileAnalysis.security?.length > 0) {
          analysisResults.security.vulnerabilities.push({
            file: relative(params.projectPath, file),
            issues: fileAnalysis.security
          });
        }
        
        // Aggregate database issues
        if (fileAnalysis.database?.length > 0) {
          analysisResults.database.queries.push({
            file: relative(params.projectPath, file),
            queries: fileAnalysis.database
          });
        }
        
        // Aggregate standards issues
        if (fileAnalysis.standards?.length > 0) {
          analysisResults.standards.issues.push({
            file: relative(params.projectPath, file),
            issues: fileAnalysis.standards
          });
        }
      } catch (error) {
        // Continue analyzing other files
      }
    }
    
    // Generate summaries
    analysisResults.security.summary = this.generateSecuritySummary(analysisResults.security.vulnerabilities);
    analysisResults.database.summary = this.generateDatabaseSummary(analysisResults.database.queries);
    analysisResults.standards.summary = this.generateStandardsSummary(analysisResults.standards.issues);
    
    return analysisResults;
  }

  /**
   * Analyze individual file for WordPress-specific patterns
   */
  private async analyzeFile(file: string, content: string, params: any): Promise<any> {
    const analysis: any = {
      filePath: relative(params.projectPath, file),
      fileName: basename(file),
      size: content.length,
      lines: content.split('\n').length,
      security: [],
      database: [],
      standards: []
    };
    
    // Check for plugin header (main plugin file)
    if (content.includes('Plugin Name:') && content.includes('*/')) {
      analysis.isMainPluginFile = true;
      analysis.pluginHeaders = this.extractPluginHeaders(content);
    }
    
    // Security checks
    if (content.match(/\$_(GET|POST|REQUEST|SERVER|COOKIE)\[/)) {
      analysis.security.push({
        type: 'INPUT_VALIDATION',
        pattern: 'Direct superglobal usage without sanitization'
      });
    }
    
    if (content.includes('$wpdb->query') && !content.includes('$wpdb->prepare')) {
      analysis.security.push({
        type: 'SQL_INJECTION',
        pattern: 'Database query without prepare statement'
      });
    }
    
    if (content.match(/wp_ajax_\w+/) && !content.includes('check_ajax_referer')) {
      analysis.security.push({
        type: 'NONCE_MISSING',
        pattern: 'AJAX handler without nonce verification'
      });
    }
    
    if (content.includes('add_menu_page') && !content.includes('current_user_can')) {
      analysis.security.push({
        type: 'CAPABILITY_CHECK',
        pattern: 'Admin page without capability check'
      });
    }
    
    // Database patterns
    if (content.includes('$wpdb')) {
      const queries = content.match(/\$wpdb->(query|get_results|get_var|get_row)/g);
      if (queries) {
        analysis.database = queries.map(q => ({
          type: q.replace('$wpdb->', ''),
          hasPrepare: content.includes('$wpdb->prepare')
        }));
      }
    }
    
    // Standards checks
    if (content.match(/function [A-Z]/)) {
      analysis.standards.push({
        type: 'NAMING_CONVENTION',
        pattern: 'Function name starts with uppercase (should be lowercase)'
      });
    }
    
    if (!content.includes('defined') && !content.includes('ABSPATH')) {
      analysis.standards.push({
        type: 'DIRECT_ACCESS',
        pattern: 'Missing direct file access prevention'
      });
    }
    
    return analysis;
  }

  /**
   * Extract directory structure from file list
   */
  private extractDirectoryStructure(files: string[], projectPath: string): string[] {
    const directories = new Set<string>();
    
    for (const file of files) {
      const dir = dirname(relative(projectPath, file));
      if (dir && dir !== '.') {
        directories.add(dir);
      }
    }
    
    return Array.from(directories).sort();
  }

  /**
   * Extract plugin headers from main file
   */
  private extractPluginHeaders(content: string): any {
    const headers: any = {};
    const headerPattern = /\*\s*([^:]+):\s*(.+)/g;
    const headerBlock = content.match(/\/\*\*([\s\S]*?)\*\//);
    
    if (headerBlock) {
      let match;
      while ((match = headerPattern.exec(headerBlock[1])) !== null) {
        headers[match[1].trim()] = match[2].trim();
      }
    }
    
    return headers;
  }

  /**
   * Generate security summary
   */
  private generateSecuritySummary(vulnerabilities: any[]): any {
    const summary = {
      totalFiles: vulnerabilities.length,
      totalIssues: 0,
      byType: {} as any
    };
    
    for (const fileVulns of vulnerabilities) {
      for (const issue of fileVulns.issues) {
        summary.totalIssues++;
        summary.byType[issue.type] = (summary.byType[issue.type] || 0) + 1;
      }
    }
    
    return summary;
  }

  /**
   * Generate database summary
   */
  private generateDatabaseSummary(queries: any[]): any {
    const summary = {
      totalFiles: queries.length,
      totalQueries: 0,
      unsafeQueries: 0
    };
    
    for (const fileQueries of queries) {
      for (const query of fileQueries.queries) {
        summary.totalQueries++;
        if (!query.hasPrepare) {
          summary.unsafeQueries++;
        }
      }
    }
    
    return summary;
  }

  /**
   * Generate standards summary
   */
  private generateStandardsSummary(issues: any[]): any {
    const summary = {
      totalFiles: issues.length,
      totalIssues: 0,
      byType: {} as any
    };
    
    for (const fileIssues of issues) {
      for (const issue of fileIssues.issues) {
        summary.totalIssues++;
        summary.byType[issue.type] = (summary.byType[issue.type] || 0) + 1;
      }
    }
    
    return summary;
  }
}

export default WordPressPluginReadiness;