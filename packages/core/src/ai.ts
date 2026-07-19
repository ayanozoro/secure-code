import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { Anthropic } from '@anthropic-ai/sdk';
import { OpenAI } from 'openai';
import type { Finding, AiValidation } from './types.js';

export interface AiConfig {
  provider: 'anthropic' | 'openai';
  model: string;
  apiKey?: string;
  apiBase?: string;
}

export function getAiConfig(targetPath?: string): AiConfig | null {
  // 1. Env vars take precedence
  const providerEnv = process.env.GUARDRAIL_AI_PROVIDER;
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  const openaiKey = process.env.OPENAI_API_KEY;
  const openaiBase = process.env.OPENAI_API_BASE;

  let provider: 'anthropic' | 'openai' | null = null;

  if (providerEnv === 'anthropic' || providerEnv === 'openai') {
    provider = providerEnv;
  } else if (anthropicKey) {
    provider = 'anthropic';
  } else if (openaiKey || openaiBase) {
    provider = 'openai';
  }

  if (provider) {
    const defaultModel = provider === 'anthropic' ? 'claude-3-5-haiku-20241022' : 'gpt-4o-mini';
    const model = process.env.GUARDRAIL_AI_MODEL || defaultModel;
    return {
      provider,
      model,
      apiKey: provider === 'anthropic' ? anthropicKey : (openaiKey || 'local-key'),
      apiBase: openaiBase
    };
  }

  // 2. Fallback to reading local .guardrail/config.json
  const searchPath = targetPath ? resolve(targetPath) : process.cwd();
  const configPath = join(searchPath, '.guardrail', 'config.json');
  try {
    const content = readFileSync(configPath, 'utf8');
    const parsed = JSON.parse(content);
    if (parsed.provider === 'anthropic' || parsed.provider === 'openai') {
      const defaultModel = parsed.provider === 'anthropic' ? 'claude-3-5-haiku-20241022' : 'gpt-4o-mini';
      return {
        provider: parsed.provider,
        model: parsed.model || defaultModel,
        apiKey: parsed.apiKey,
        apiBase: parsed.apiBase
      };
    }
  } catch {
    // Local config file doesn't exist or is invalid
  }

  // 3. Fallback to reading global ~/.guardrail/config.json
  try {
    const globalPath = join(homedir(), '.guardrail', 'config.json');
    const content = readFileSync(globalPath, 'utf8');
    const parsed = JSON.parse(content);
    if (parsed.provider === 'anthropic' || parsed.provider === 'openai') {
      const defaultModel = parsed.provider === 'anthropic' ? 'claude-3-5-haiku-20241022' : 'gpt-4o-mini';
      return {
        provider: parsed.provider,
        model: parsed.model || defaultModel,
        apiKey: parsed.apiKey,
        apiBase: parsed.apiBase
      };
    }
  } catch {
    // Global config file doesn't exist or is invalid
  }

  return null;
}


export async function validateFinding(
  finding: Finding,
  snippet: string,
  config: AiConfig
): Promise<AiValidation> {
  const prompt = `You are a security expert code reviewer.
Review the following static analysis finding and the surrounding code context.
Determine if the finding is a true positive (confirmed vulnerability) or a false positive.

Static Analysis Finding Details:
- Engine: ${finding.engine}
- Rule ID: ${finding.ruleId}
- Message: ${finding.message}
- File Path: ${finding.filePath}
- Line Number: ${finding.line}

Surrounding Code Context (±5 lines around finding line):
\`\`\`typescript
${snippet}
\`\`\`

You must respond ONLY with a JSON object. Do not write any explanations before or after the JSON.
The JSON object must match this schema:
{
  "confirmed": boolean,
  "severity": "low" | "medium" | "high" | "critical",
  "explanation": "Brief explanation of why this is or is not a vulnerability, and the security implications.",
  "suggested_fix_diff": "A code diff or suggested fix showing how to rewrite the code safely.",
  "false_positive": boolean
}

JSON response:`;

  let responseText = '';

  if (config.provider === 'anthropic') {
    const anthropic = new Anthropic({ apiKey: config.apiKey });
    const msg = await anthropic.messages.create({
      model: config.model,
      max_tokens: 1500,
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.1
    });
    responseText = msg.content[0]?.type === 'text' ? msg.content[0].text : '';
  } else {
    const openai = new OpenAI({
      apiKey: config.apiKey,
      baseURL: config.apiBase
    });
    const completion = await openai.chat.completions.create({
      model: config.model,
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.1,
      max_tokens: 1500,
      response_format: { type: 'json_object' }
    });
    responseText = completion.choices[0]?.message?.content || '';
  }


  return parseValidationResponse(responseText, finding.severity);
}

function parseValidationResponse(text: string, defaultSeverity: Finding['severity']): AiValidation {
  try {
    let cleanText = text.trim();
    // Strip markdown code blocks if the model wrapped it in ```json ... ```
    if (cleanText.startsWith('```')) {
      const start = cleanText.indexOf('{');
      const end = cleanText.lastIndexOf('}');
      if (start !== -1 && end !== -1) {
        cleanText = cleanText.substring(start, end + 1);
      }
    }

    const parsed = JSON.parse(cleanText);

    // Normalize keys and check values
    const confirmed = typeof parsed.confirmed === 'boolean' ? parsed.confirmed : true;
    const falsePositive = typeof parsed.false_positive === 'boolean' ? parsed.false_positive : !confirmed;

    let severity: Finding['severity'] = defaultSeverity;
    const parsedSeverity = String(parsed.severity || '').toLowerCase();
    if (['low', 'medium', 'high', 'critical'].includes(parsedSeverity)) {
      severity = parsedSeverity as Finding['severity'];
    }

    return {
      confirmed,
      severity,
      explanation: parsed.explanation || 'No explanation provided.',
      suggestedFixDiff: parsed.suggested_fix_diff || 'No suggestion provided.',
      falsePositive
    };
  } catch (err) {
    // Graceful fallback for parse failure
    return {
      confirmed: true,
      severity: defaultSeverity,
      explanation: `Could not parse AI response: ${(err as Error).message}. Raw response: ${text.substring(0, 100)}`,
      suggestedFixDiff: '',
      falsePositive: false
    };
  }
}
