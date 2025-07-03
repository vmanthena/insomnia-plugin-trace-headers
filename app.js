const crypto = require('crypto');

// =============================================================================
// CONSTANTS AND VALIDATION PATTERNS
// =============================================================================

// Display name prefix constant
const DISPLAY_NAME_PREFIX = 'Trace Headers:';

// Default values
const DEFAULTS = {
  VERSION: '00',
  SAMPLED: true,
  VENDOR_KEY: 'vendor',
  VENDOR_VALUE: 'value',
  PRIORITY: '1',
  ORIGIN: 'synthetics',
  ENVIRONMENT: 'production',
  SERVICE: 'api',
  APP_ID: 'unknown',
  BAGGAGE_KEY: 'userid',
  BAGGAGE_VALUE: '12345',
  TRACE_LENGTH: '128',
  ACCOUNT_ID: '1234567',
  NEW_RELIC_APP_ID: '7654321',
  DATASET: 'my-service',
  SAMPLE_RATE: '1',
  PATH: '/api/v1/users',
  FORMAT: 'hex',
  SECRET_KEY: 'your-tyk-secret-key',
  API_VERSION: 'v1',
  MACHINE_ID: 0,
  EPOCH_TYPE: 'twitter',
  CUSTOM_EPOCH: 1288834974657,
  CORRELATION_FORMAT: 'uuid',
  USER_FORMAT: 'numeric',
  TRACE_FORMAT: '{traceId}-{spanId}',
  DYNATRACE_APP_ID: 'APPLICATION-12345',
  GUID_FORMAT: 'N', // Default to 'N' format (no hyphens)
  BATCH_COUNT: 10,
  TARGET_URL: 'https://api.example.com',
  PREFIX: 'req',
  TIMESTAMP_FORMAT: 'iso',
  TEMPLATE: 'trace-{date}-{random}-{sequence}',
  SALT: 'default-salt'
};

// Regex patterns for validation
const PATTERNS = {
  HEX_2: /^[0-9a-fA-F]{2}$/,
  HEX_FLEXIBLE: /^[0-9a-fA-F]+$/,
  ALPHANUMERIC: /^[a-zA-Z0-9_-]+$/,
  ALPHANUMERIC_DOT: /^[a-zA-Z0-9._-]+$/,
  NUMERIC: /^\d+$/,
  PRIORITY: /^-?[0-2]$/,
  VERSION_STRING: /^v?\d+(\.\d+)*$/,
  BOOLEAN_STRING: /^(true|false|1|0)$/i,
  SERVICE_NAME: /^[a-zA-Z0-9._-]+$/,
  ENVIRONMENT_NAME: /^[a-zA-Z0-9._-]+$/,
  PATH: /^\/[a-zA-Z0-9\/_-]*$/,
  FORMAT_ENUM: /^(hex|uuid|numeric)$/,
  TRACE_LENGTH: /^(64|128)$/,
  SAMPLE_RATE: /^(1|10|100)$/,
  EPOCH_TYPE: /^(twitter|discord|unix|custom)$/,
  CORRELATION_FORMAT: /^(uuid|hex64|hex128|numeric)$/,
  USER_FORMAT: /^(numeric|uuid|hex)$/,
  TRACE_FORMAT: /^[a-zA-Z0-9{}_-]+$/,
  KEY_VALUE: /^[a-zA-Z0-9._-]+$/,
  APP_ID: /^[a-zA-Z0-9._-]+$/,
  DATADOG_PRIORITY: /^(-1|0|1|2)$/,
  GUID_FORMAT: /^(N|D|B|P)$/,
  URL: /^https?:\/\/[a-zA-Z0-9.-]+/,
  TIMESTAMP_FORMAT: /^(iso|unix|custom)$/,
  TEMPLATE_STRING: /^[a-zA-Z0-9{}_.-]+$/
};

// Valid enum values
const ENUMS = {
  PRIORITY: ['-1', '0', '1', '2'],
  TRACE_LENGTH: ['64', '128'],
  SAMPLE_RATE: ['1', '10', '100'],
  FORMAT: ['hex', 'uuid', 'numeric'],
  EPOCH_TYPE: ['twitter', 'discord', 'unix', 'custom'],
  CORRELATION_FORMAT: ['uuid', 'hex64', 'hex128', 'numeric'],
  USER_FORMAT: ['numeric', 'uuid', 'hex'],
  GUID_FORMAT: ['N', 'D', 'B', 'P'],
  TIMESTAMP_FORMAT: ['iso', 'unix', 'custom']
};

// =============================================================================
// GLOBAL STATE FOR ADVANCED FEATURES
// =============================================================================

let sequenceCounter = 1;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function randomHex(length) {
  try {
    return crypto.randomBytes(length).toString('hex');
  } catch (e) {
    let result = '';
    for (let i = 0; i < length * 2; i++) {
      result += Math.floor(Math.random() * 16).toString(16);
    }
    return result;
  }
}

function randomUUID() {
  try {
    const bytes = crypto.randomBytes(16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = bytes.toString('hex');
    return `${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20,32)}`;
  } catch (e) {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c == 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}

function formatGUID(uuid, format) {
  // Remove existing hyphens to get base format
  const clean = uuid.replace(/-/g, '');
  
  switch (format) {
    case 'N': // 32 digits: 00000000000000000000000000000000
      return clean;
    case 'D': // 32 digits separated by hyphens: 00000000-0000-0000-0000-000000000000
      return `${clean.substring(0,8)}-${clean.substring(8,12)}-${clean.substring(12,16)}-${clean.substring(16,20)}-${clean.substring(20,32)}`;
    case 'B': // 32 digits separated by hyphens, enclosed in braces: {00000000-0000-0000-0000-000000000000}
      return `{${clean.substring(0,8)}-${clean.substring(8,12)}-${clean.substring(12,16)}-${clean.substring(16,20)}-${clean.substring(20,32)}}`;
    case 'P': // 32 digits separated by hyphens, enclosed in parentheses: (00000000-0000-0000-0000-000000000000)
      return `(${clean.substring(0,8)}-${clean.substring(8,12)}-${clean.substring(12,16)}-${clean.substring(16,20)}-${clean.substring(20,32)})`;
    default:
      return clean; // Default to 'N' format
  }
}

function randomNumber() {
  return Math.floor(Math.random() * 9007199254740991).toString();
}

function timestamp() {
  return Math.floor(Date.now() / 1000).toString();
}

function safeBase64(str) {
  try {
    return Buffer.from(str).toString('base64');
  } catch (e) {
    return btoa ? btoa(str) : 'base64-error';
  }
}

function generateSnowflake(epoch = 1288834974657, machineId = 0) {
  const ts = Date.now() - epoch;
  const machine = Math.max(0, Math.min(1023, machineId));
  const seq = Math.floor(Math.random() * 4096);
  
  try {
    if (typeof BigInt !== 'undefined') {
      const id = (BigInt(ts) << 22n) | (BigInt(machine) << 12n) | BigInt(seq);
      return id.toString();
    }
  } catch (e) {
    // Fallback for environments without BigInt
  }
  
  return `${ts}${machine.toString().padStart(4, '0')}${seq.toString().padStart(4, '0')}`;
}

// Smart header detection based on URL
function detectCloudProvider(url) {
  const urlLower = url.toLowerCase();
  const headers = {};
  
  // AWS detection
  if (urlLower.includes('amazonaws.com') || urlLower.includes('aws.')) {
    headers['X-Amzn-Trace-Id'] = `Root=1-${Math.floor(Date.now()/1000).toString(16)}-${randomHex(12)}`;
    headers['X-Amz-Request-Id'] = randomUUID();
    return { provider: 'AWS', headers };
  }
  
  // Google Cloud detection
  if (urlLower.includes('googleapis.com') || urlLower.includes('google.com') || urlLower.includes('gcp.')) {
    headers['X-Goog-Trace'] = `${randomHex(16)}/${randomNumber()}`;
    headers['X-Cloud-Trace-Context'] = `${randomHex(16)}/${randomNumber()};o=1`;
    return { provider: 'Google Cloud', headers };
  }
  
  // Azure detection
  if (urlLower.includes('azure.com') || urlLower.includes('microsoft.com')) {
    headers['x-ms-request-id'] = randomUUID();
    headers['x-ms-client-request-id'] = randomUUID();
    return { provider: 'Azure', headers };
  }
  
  // CloudFlare detection
  if (urlLower.includes('cloudflare.com') || urlLower.includes('cf-ray')) {
    const dcs = ['DFW', 'LAX', 'ORD', 'JFK', 'LHR'];
    const dc = dcs[Math.floor(Math.random() * dcs.length)];
    headers['CF-Ray'] = `${randomHex(8)}-${dc}`;
    return { provider: 'CloudFlare', headers };
  }
  
  // Oracle Cloud detection
  if (urlLower.includes('oracle.com') || urlLower.includes('oci.')) {
    headers['x-oracle-request-id'] = randomUUID();
    return { provider: 'Oracle Cloud', headers };
  }
  
  // Default distributed tracing headers
  headers['traceparent'] = `00-${randomHex(16)}-${randomHex(8)}-01`;
  headers['X-Request-ID'] = randomUUID();
  headers['X-Correlation-ID'] = randomUUID();
  
  return { provider: 'Generic', headers };
}

// Template replacement function
function processTemplate(template) {
  const now = new Date();
  const replacements = {
    '{date}': now.toISOString().split('T')[0],
    '{time}': now.toTimeString().split(' ')[0].replace(/:/g, ''),
    '{random}': randomHex(4),
    '{uuid}': randomUUID(),
    '{sequence}': String(sequenceCounter++),
    '{timestamp}': Math.floor(Date.now() / 1000),
    '{traceId}': randomHex(16),
    '{spanId}': randomHex(8),
    '{year}': now.getFullYear(),
    '{month}': (now.getMonth() + 1).toString().padStart(2, '0'),
    '{day}': now.getDate().toString().padStart(2, '0'),
    '{hour}': now.getHours().toString().padStart(2, '0'),
    '{minute}': now.getMinutes().toString().padStart(2, '0'),
    '{second}': now.getSeconds().toString().padStart(2, '0'),
    '{userAgent}': 'Insomnia-Plugin-Trace-Headers/2.0',
    '{hostname}': 'localhost',
    '{requestId}': randomUUID(),
    '{correlationId}': randomUUID(),
    '{sessionId}': `sess_${randomHex(8)}`,
    '{randomNumber}': Math.floor(Math.random() * 1000000),
    '{base64Random}': safeBase64(randomHex(8)),
    '{unixTimestamp}': Math.floor(Date.now() / 1000),
    '{isoTimestamp}': now.toISOString()
  };
  
  let result = template;
  Object.entries(replacements).forEach(([key, value]) => {
    result = result.replace(new RegExp(key.replace(/[{}]/g, '\\$&'), 'g'), value);
  });
  
  return result;
}

// Comprehensive parameter validation function
function validateParam(value, type, pattern, enumValues, defaultValue) {
  // Handle undefined/null
  if (value === undefined || value === null) {
    return defaultValue;
  }
  
  // Convert to string for pattern matching (except for numbers and booleans)
  const stringValue = String(value);
  
  // Handle different parameter types
  switch (type) {
    case 'boolean':
      if (value === true || value === 'true' || value === '1' || value === 1) {
        return true;
      }
      if (value === false || value === 'false' || value === '0' || value === 0) {
        return false;
      }
      // If we get unexpected values (like environment variable names), use default
      return defaultValue;
      
    case 'number':
      const num = Number(value);
      if (isNaN(num) || num < 0) {
        return defaultValue;
      }
      return num;
      
    case 'enum':
      if (enumValues && enumValues.includes(stringValue)) {
        return stringValue;
      }
      return defaultValue;
      
    case 'string':
    default:
      // Handle environment variable mishaps (when user selects "Environment value" by mistake)
      if (value === true || value === false) {
        return defaultValue;
      }
      
      // Validate against pattern if provided
      if (pattern && !pattern.test(stringValue)) {
        return defaultValue;
      }
      
      return stringValue || defaultValue;
  }
}

// =============================================================================
// TEMPLATE TAGS
// =============================================================================

module.exports.templateTags = [
  // =============================================================================
  // ADVANCED FEATURES - BATCH & SMART GENERATION
  // =============================================================================
  
  // Batch Generation
  {
    name: 'batch_trace_headers',
    displayName: `${DISPLAY_NAME_PREFIX} Batch Generator`,
    description: 'Generate multiple trace headers at once (max 100)',
    args: [
      {
        displayName: 'Count',
        description: 'Number of headers to generate (max 100)',
        type: 'number',
        defaultValue: DEFAULTS.BATCH_COUNT
      },
      {
        displayName: 'Format',
        description: 'Output format',
        type: 'enum',
        defaultValue: 'json',
        options: [
          { displayName: 'JSON', value: 'json' },
          { displayName: 'Headers', value: 'headers' },
          { displayName: 'Simple List', value: 'list' }
        ]
      }
    ],
    async run(context, count, format) {
      const safeCount = validateParam(count, 'number', null, null, DEFAULTS.BATCH_COUNT);
      const safeFormat = validateParam(format, 'enum', null, ['json', 'headers', 'list'], 'json');
      const actualCount = Math.min(Math.max(1, safeCount), 100);
      
      const headers = [];
      for (let i = 0; i < actualCount; i++) {
        headers.push({
          id: i + 1,
          traceId: randomHex(16),
          spanId: randomHex(8),
          requestId: randomUUID(),
          correlationId: randomUUID(),
          timestamp: new Date().toISOString(),
          traceparent: `00-${randomHex(16)}-${randomHex(8)}-01`
        });
      }
      
      switch (safeFormat) {
        case 'headers':
          return headers.map(h => `traceparent: ${h.traceparent}\nx-request-id: ${h.requestId}`).join('\n\n');
        case 'list':
          return headers.map(h => h.traceparent).join('\n');
        default:
          return JSON.stringify(headers, null, 2);
      }
    }
  },

  // Smart Context-Aware Headers
  {
    name: 'smart_trace_header',
    displayName: `${DISPLAY_NAME_PREFIX} Smart Generator`,
    description: 'Auto-detect and generate appropriate headers based on URL',
    args: [
      {
        displayName: 'Target URL',
        description: 'URL to analyze for appropriate headers',
        type: 'string',
        defaultValue: DEFAULTS.TARGET_URL
      },
      {
        displayName: 'Output Format',
        description: 'How to display the headers',
        type: 'enum',
        defaultValue: 'json',
        options: [
          { displayName: 'JSON Object', value: 'json' },
          { displayName: 'Header Format', value: 'headers' },
          { displayName: 'Curl Format', value: 'curl' }
        ]
      }
    ],
    async run(context, url, outputFormat) {
      const safeUrl = validateParam(url, 'string', PATTERNS.URL, null, DEFAULTS.TARGET_URL);
      const safeFormat = validateParam(outputFormat, 'enum', null, ['json', 'headers', 'curl'], 'json');
      const detection = detectCloudProvider(safeUrl);
      
      const result = {
        detectedProvider: detection.provider,
        targetUrl: safeUrl,
        generatedHeaders: detection.headers,
        timestamp: new Date().toISOString(),
        recommendations: `Based on URL analysis, generated ${Object.keys(detection.headers).length} appropriate headers`
      };
      
      switch (safeFormat) {
        case 'headers':
          return Object.entries(detection.headers).map(([key, value]) => `${key}: ${value}`).join('\n');
        case 'curl':
          const curlHeaders = Object.entries(detection.headers).map(([key, value]) => `-H "${key}: ${value}"`).join(' ');
          return `curl ${curlHeaders} ${safeUrl}`;
        default:
          return JSON.stringify(result, null, 2);
      }
    }
  },

  // Sequential/Incremental IDs
  {
    name: 'sequential_id',
    displayName: `${DISPLAY_NAME_PREFIX} Sequential ID`,
    description: 'Generate sequential IDs for testing with custom prefixes',
    args: [
      {
        displayName: 'Prefix',
        description: 'ID prefix',
        type: 'string',
        defaultValue: DEFAULTS.PREFIX
      },
      {
        displayName: 'Include Timestamp',
        description: 'Include timestamp in ID',
        type: 'boolean',
        defaultValue: true
      }
    ],
    async run(context, prefix, includeTimestamp) {
      const safePrefix = validateParam(prefix, 'string', PATTERNS.ALPHANUMERIC, null, DEFAULTS.PREFIX);
      const includeTs = validateParam(includeTimestamp, 'boolean', null, null, true);
      
      const parts = [safePrefix];
      if (includeTs) {
        parts.push(Date.now());
      }
      parts.push(sequenceCounter++);
      
      return parts.join('_');
    }
  },

  // Parent-Child Trace Relationships
  {
    name: 'parent_child_trace',
    displayName: `${DISPLAY_NAME_PREFIX} Parent-Child Trace`,
    description: 'Generate related parent and child trace IDs',
    args: [
      {
        displayName: 'Parent Trace ID',
        description: 'Existing parent trace ID (leave empty to generate)',
        type: 'string',
        defaultValue: ''
      },
      {
        displayName: 'Child Count',
        description: 'Number of child traces to generate',
        type: 'number',
        defaultValue: 1
      }
    ],
    async run(context, parentTraceId, childCount) {
      const traceId = parentTraceId || randomHex(16);
      const safeChildCount = validateParam(childCount, 'number', null, null, 1);
      const actualChildCount = Math.min(Math.max(1, safeChildCount), 10);
      
      const parentSpanId = randomHex(8);
      const children = [];
      
      for (let i = 0; i < actualChildCount; i++) {
        const childSpanId = randomHex(8);
        children.push({
          traceparent: `00-${traceId}-${childSpanId}-01`,
          spanId: childSpanId,
          parentSpanId: parentSpanId,
          operation: `child-operation-${i + 1}`
        });
      }
      
      return JSON.stringify({
        traceId: traceId,
        parent: {
          traceparent: `00-${traceId}-${parentSpanId}-01`,
          spanId: parentSpanId,
          operation: 'parent-operation'
        },
        children: children,
        relationships: children.map(child => `${parentSpanId} → ${child.spanId}`),
        timestamp: new Date().toISOString()
      }, null, 2);
    }
  },

  // Timestamp-Based IDs
  {
    name: 'timestamped_id',
    displayName: `${DISPLAY_NAME_PREFIX} Timestamped ID`,
    description: 'Generate time-based correlation IDs with various formats',
    args: [
      {
        displayName: 'Format',
        description: 'Timestamp format',
        type: 'enum',
        defaultValue: DEFAULTS.TIMESTAMP_FORMAT,
        options: [
          { displayName: 'ISO 8601', value: 'iso' },
          { displayName: 'Unix Timestamp', value: 'unix' },
          { displayName: 'Custom (YYYYMMDDHHMM)', value: 'custom' }
        ]
      },
      {
        displayName: 'Add Random Suffix',
        description: 'Add random suffix to ensure uniqueness',
        type: 'boolean',
        defaultValue: true
      }
    ],
    async run(context, format, addRandom) {
      const safeFormat = validateParam(format, 'enum', null, ENUMS.TIMESTAMP_FORMAT, DEFAULTS.TIMESTAMP_FORMAT);
      const includeRandom = validateParam(addRandom, 'boolean', null, null, true);
      const now = new Date();
      let timestamp;
      
      switch (safeFormat) {
        case 'iso':
          timestamp = now.toISOString().replace(/[-:\.]/g, '');
          break;
        case 'unix':
          timestamp = Math.floor(now.getTime() / 1000);
          break;
        case 'custom':
          timestamp = now.getFullYear() + 
                     (now.getMonth() + 1).toString().padStart(2, '0') +
                     now.getDate().toString().padStart(2, '0') +
                     now.getHours().toString().padStart(2, '0') +
                     now.getMinutes().toString().padStart(2, '0');
          break;
        default:
          timestamp = now.toISOString().replace(/[-:\.]/g, '');
      }
      
      return includeRandom ? `${timestamp}_${randomHex(8)}` : timestamp;
    }
  },

  // Header Template Builder
  {
    name: 'header_template',
    displayName: `${DISPLAY_NAME_PREFIX} Template Builder`,
    description: 'Build custom header templates with 12+ placeholders',
    args: [
      {
        displayName: 'Template',
        description: 'Header template with placeholders: {date}, {time}, {random}, {uuid}, {sequence}, {traceId}, {spanId}, {timestamp}, {year}, {month}, {day}, {hour}, {minute}, {second}, etc.',
        type: 'string',
        defaultValue: DEFAULTS.TEMPLATE
      }
    ],
    async run(context, template) {
      const safeTemplate = validateParam(template, 'string', PATTERNS.TEMPLATE_STRING, null, DEFAULTS.TEMPLATE);
      return processTemplate(safeTemplate);
    }
  },

  // Debug/Testing Mode
  {
    name: 'debug_trace_info',
    displayName: `${DISPLAY_NAME_PREFIX} Debug Info`,
    description: 'Generate comprehensive debug information for tracing',
    args: [
      {
        displayName: 'Include Performance',
        description: 'Include performance metrics',
        type: 'boolean',
        defaultValue: true
      },
      {
        displayName: 'Include System Info',
        description: 'Include system information',
        type: 'boolean',
        defaultValue: true
      }
    ],
    async run(context, includePerf, includeSystem) {
      const startTime = Date.now();
      const perfEnabled = validateParam(includePerf, 'boolean', null, null, true);
      const systemEnabled = validateParam(includeSystem, 'boolean', null, null, true);
      
      const debugInfo = {
        timestamp: new Date().toISOString(),
        environment: 'development',
        version: '2.0.0',
        requestId: randomUUID(),
        sessionId: `sess_${randomHex(8)}`,
        debugEnabled: true,
        traceInfo: {
          traceId: randomHex(16),
          spanId: randomHex(8),
          parentSpanId: randomHex(8),
          sampled: true,
          flags: '01'
        },
        metadata: {
          userAgent: 'Insomnia-Plugin-Trace-Headers',
          source: 'trace-headers-plugin',
          pluginVersion: '2.0.0',
          generatedAt: Date.now(),
          templateTagsAvailable: 80
        }
      };

      if (perfEnabled) {
        debugInfo.performance = {
          generationTime: `${Date.now() - startTime}ms`,
          sequenceNumber: sequenceCounter++,
          memoryUsage: 'not-available-in-browser',
          timestamp: Date.now()
        };
      }

      if (systemEnabled) {
        debugInfo.systemInfo = {
          platform: 'browser',
          nodeVersion: 'browser-environment',
          cryptoSupport: typeof crypto !== 'undefined',
          bigIntSupport: typeof BigInt !== 'undefined'
        };
      }

      return JSON.stringify(debugInfo, null, 2);
    }
  },

  // =============================================================================
  // ADDITIONAL CLOUD PROVIDERS
  // =============================================================================
  
  // Oracle Cloud
  {
    name: 'oracle_request_id',
    displayName: `${DISPLAY_NAME_PREFIX} Oracle Cloud Request ID`,
    description: 'Generate Oracle Cloud Infrastructure request ID',
    args: [
      {
        displayName: 'GUID Format',
        description: 'GUID format',
        type: 'enum',
        defaultValue: DEFAULTS.GUID_FORMAT,
        options: [
          { displayName: 'N (df9843665f310d8374507e34cb60954e)', value: 'N' },
          { displayName: 'D (df984366-5f31-0d83-7450-7e34cb60954e)', value: 'D' },
          { displayName: 'B ({df984366-5f31-0d83-7450-7e34cb60954e})', value: 'B' },
          { displayName: 'P ((df984366-5f31-0d83-7450-7e34cb60954e))', value: 'P' }
        ]
      }
    ],
    async run(context, guidFormat) {
      const safeGuidFormat = validateParam(guidFormat, 'enum', null, ENUMS.GUID_FORMAT, DEFAULTS.GUID_FORMAT);
      const uuid = randomUUID();
      return formatGUID(uuid, safeGuidFormat);
    }
  },

  // IBM Cloud
  {
    name: 'ibm_trace_id',
    displayName: `${DISPLAY_NAME_PREFIX} IBM Cloud Trace ID`,
    description: 'Generate IBM Cloud trace ID',
    args: [],
    async run() {
      return `ibm-trace-${randomHex(16)}-${Date.now()}`;
    }
  },

  // Alibaba Cloud
  {
    name: 'alibaba_request_id',
    displayName: `${DISPLAY_NAME_PREFIX} Alibaba Cloud Request ID`,
    description: 'Generate Alibaba Cloud request ID',
    args: [],
    async run() {
      return `${randomHex(8)}-${randomHex(4)}-${randomHex(4)}-${randomHex(4)}-${randomHex(12)}`.toUpperCase();
    }
  },

  // =============================================================================
  // COMPLIANCE & SECURITY
  // =============================================================================
  
  // Privacy-Safe ID
  {
    name: 'privacy_safe_id',
    displayName: `${DISPLAY_NAME_PREFIX} Privacy-Safe ID`,
    description: 'Generate privacy-compliant correlation ID (GDPR compliant)',
    args: [],
    async run(context) {
      // No personally identifiable information
      return `anon_${randomHex(16)}_${Math.floor(Date.now() / 1000)}`;
    }
  },

  // Financial Services Compliant
  {
    name: 'financial_trace_id',
    displayName: `${DISPLAY_NAME_PREFIX} Financial Trace ID`,
    description: 'Generate financial services compliant trace ID',
    args: [
      {
        displayName: 'Institution Code',
        description: 'Optional institution identifier',
        type: 'string',
        defaultValue: 'FIN'
      }
    ],
    async run(context, institutionCode) {
      const safeCode = validateParam(institutionCode, 'string', PATTERNS.ALPHANUMERIC, null, 'FIN');
      // Format: FIN-YYYYMMDD-HHMMSS-RANDOM
      const now = new Date();
      const date = now.toISOString().split('T')[0].replace(/-/g, '');
      const time = now.toTimeString().split(' ')[0].replace(/:/g, '');
      return `${safeCode}-${date}-${time}-${randomHex(8).toUpperCase()}`;
    }
  },

  // GDPR Compliant ID
  {
    name: 'gdpr_compliant_id',
    displayName: `${DISPLAY_NAME_PREFIX} GDPR Compliant ID`,
    description: 'Generate GDPR-compliant trace ID (pseudonymized)',
    args: [],
    async run(context) {
      // Pseudonymized identifier with no personal data
      return `gdpr_${randomHex(12)}_${Math.floor(Date.now() / 86400000)}${randomHex(4)}`;
    }
  },

  // Pseudonymized Identifier
  {
    name: 'pseudonymized_id',
    displayName: `${DISPLAY_NAME_PREFIX} Pseudonymized ID`,
    description: 'Generate pseudonymized identifier (non-reversible)',
    args: [
      {
        displayName: 'Salt',
        description: 'Optional salt for pseudonymization',
        type: 'string',
        defaultValue: DEFAULTS.SALT
      }
    ],
    async run(context, salt) {
      const safeSalt = validateParam(salt, 'string', PATTERNS.ALPHANUMERIC, null, DEFAULTS.SALT);
      // Create a pseudonymized ID that's non-reversible
      const baseId = randomHex(16);
      const pseudoId = safeBase64(`${safeSalt}:${baseId}:${Date.now()}`);
      return `pseudo_${pseudoId.replace(/[+/=]/g, '').substring(0, 16)}`;
    }
  },

  // =============================================================================
  // ORIGINAL TRACE HEADERS (with updated displayName prefix)
  // =============================================================================

  // W3C Trace Context / OpenTelemetry
  {
    name: 'traceparent',
    displayName: `${DISPLAY_NAME_PREFIX} W3C Traceparent`,
    description: 'Generate W3C traceparent header for OpenTelemetry distributed tracing',
    args: [
      {
        displayName: 'Version',
        description: 'W3C trace context version (hex 00-FF)',
        type: 'string',
        defaultValue: DEFAULTS.VERSION
      },
      {
        displayName: 'Sampled',
        description: 'Whether the trace is sampled',
        type: 'boolean',
        defaultValue: DEFAULTS.SAMPLED
      }
    ],
    async run(context, version, sampled) {
      const versionStr = validateParam(version, 'string', PATTERNS.HEX_2, null, DEFAULTS.VERSION);
      const isSampled = validateParam(sampled, 'boolean', null, null, DEFAULTS.SAMPLED);
      
      const traceId = randomHex(16);
      const spanId = randomHex(8);
      const flags = isSampled ? '01' : '00';
      return `${versionStr}-${traceId}-${spanId}-${flags}`;
    }
  },

  {
    name: 'tracestate',
    displayName: `${DISPLAY_NAME_PREFIX} W3C Tracestate`,
    description: 'Generate W3C tracestate header',
    args: [
      {
        displayName: 'Vendor Key',
        description: 'Vendor-specific key (alphanumeric, dash, underscore)',
        type: 'string',
        defaultValue: DEFAULTS.VENDOR_KEY
      },
      {
        displayName: 'Vendor Value',
        description: 'Vendor-specific value (alphanumeric, dash, underscore)',
        type: 'string',
        defaultValue: DEFAULTS.VENDOR_VALUE
      }
    ],
    async run(context, key, value) {
      const safeKey = validateParam(key, 'string', PATTERNS.KEY_VALUE, null, DEFAULTS.VENDOR_KEY);
      const safeValue = validateParam(value, 'string', PATTERNS.KEY_VALUE, null, DEFAULTS.VENDOR_VALUE);
      return `${safeKey}=${safeValue}`;
    }
  },

  // Datadog APM Headers
  {
    name: 'datadog_trace_id',
    displayName: `${DISPLAY_NAME_PREFIX} Datadog Trace ID`,
    description: 'Generate Datadog trace ID header',
    args: [],
    async run() {
      return randomNumber();
    }
  },

  {
    name: 'datadog_parent_id',
    displayName: `${DISPLAY_NAME_PREFIX} Datadog Parent ID`,
    description: 'Generate Datadog parent/span ID header',
    args: [],
    async run() {
      return randomNumber();
    }
  },

  {
    name: 'datadog_sampling_priority',
    displayName: `${DISPLAY_NAME_PREFIX} Datadog Sampling Priority`,
    description: 'Generate Datadog sampling priority header',
    args: [
      {
        displayName: 'Priority',
        description: 'Sampling priority level (-1, 0, 1, 2)',
        type: 'enum',
        defaultValue: DEFAULTS.PRIORITY,
        options: [
          { displayName: 'Auto Reject (-1)', value: '-1' },
          { displayName: 'Auto Keep (0)', value: '0' },
          { displayName: 'User Keep (1)', value: '1' },
          { displayName: 'User Reject (2)', value: '2' }
        ]
      }
    ],
    async run(context, priority) {
      return validateParam(priority, 'enum', null, ENUMS.PRIORITY, DEFAULTS.PRIORITY);
    }
  },

  {
    name: 'datadog_origin',
    displayName: `${DISPLAY_NAME_PREFIX} Datadog Origin`,
    description: 'Generate Datadog origin header',
    args: [
      {
        displayName: 'Origin',
        description: 'Origin type (alphanumeric, dash, underscore)',
        type: 'string',
        defaultValue: DEFAULTS.ORIGIN
      }
    ],
    async run(context, origin) {
      return validateParam(origin, 'string', PATTERNS.ALPHANUMERIC, null, DEFAULTS.ORIGIN);
    }
  },

  {
    name: 'datadog_tags',
    displayName: `${DISPLAY_NAME_PREFIX} Datadog Tags`,
    description: 'Generate Datadog tags header',
    args: [
      {
        displayName: 'Environment',
        description: 'Environment name (alphanumeric, dash, underscore, dot)',
        type: 'string',
        defaultValue: DEFAULTS.ENVIRONMENT
      },
      {
        displayName: 'Service',
        description: 'Service name (alphanumeric, dash, underscore, dot)',
        type: 'string',
        defaultValue: DEFAULTS.SERVICE
      }
    ],
    async run(context, env, service) {
      const safeEnv = validateParam(env, 'string', PATTERNS.ENVIRONMENT_NAME, null, DEFAULTS.ENVIRONMENT);
      const safeService = validateParam(service, 'string', PATTERNS.SERVICE_NAME, null, DEFAULTS.SERVICE);
      return `_dd.p.env=${safeEnv},_dd.p.service=${safeService}`;
    }
  },

  // AWS X-Ray Headers
  {
    name: 'aws_trace_id',
    displayName: `${DISPLAY_NAME_PREFIX} AWS X-Ray Trace ID`,
    description: 'Generate AWS X-Ray trace ID header',
    args: [],
    async run() {
      const ts = Math.floor(Date.now() / 1000).toString(16);
      const random = randomHex(12);
      return `Root=1-${ts}-${random}`;
    }
  },

  {
    name: 'aws_request_id',
    displayName: `${DISPLAY_NAME_PREFIX} AWS Request ID`,
    description: 'Generate AWS request ID header',
    args: [
      {
        displayName: 'GUID Format',
        description: 'GUID format (N=no hyphens, D=hyphens, B=braces, P=parentheses)',
        type: 'enum',
        defaultValue: DEFAULTS.GUID_FORMAT,
        options: [
          { displayName: 'N (df9843665f310d8374507e34cb60954e)', value: 'N' },
          { displayName: 'D (df984366-5f31-0d83-7450-7e34cb60954e)', value: 'D' },
          { displayName: 'B ({df984366-5f31-0d83-7450-7e34cb60954e})', value: 'B' },
          { displayName: 'P ((df984366-5f31-0d83-7450-7e34cb60954e))', value: 'P' }
        ]
      }
    ],
    async run(context, guidFormat) {
      const safeGuidFormat = validateParam(guidFormat, 'enum', null, ENUMS.GUID_FORMAT, DEFAULTS.GUID_FORMAT);
      const uuid = randomUUID();
      return formatGUID(uuid, safeGuidFormat);
    }
  },

  {
    name: 'aws_cf_id',
    displayName: `${DISPLAY_NAME_PREFIX} AWS CloudFront ID`,
    description: 'Generate AWS CloudFront ID header',
    args: [],
    async run() {
      return randomHex(28) + '==';
    }
  },

  {
    name: 'aws_id_2',
    displayName: `${DISPLAY_NAME_PREFIX} AWS ID 2`,
    description: 'Generate AWS x-amz-id-2 header',
    args: [],
    async run() {
      return randomHex(32) + '/abcdef+123456=';
    }
  },

  // Azure Application Insights Headers
  {
    name: 'azure_request_id',
    displayName: `${DISPLAY_NAME_PREFIX} Azure Request ID`,
    description: 'Generate Azure request ID header',
    args: [
      {
        displayName: 'GUID Format',
        description: 'GUID format (N=no hyphens, D=hyphens, B=braces, P=parentheses)',
        type: 'enum',
        defaultValue: DEFAULTS.GUID_FORMAT,
        options: [
          { displayName: 'N (df9843665f310d8374507e34cb60954e)', value: 'N' },
          { displayName: 'D (df984366-5f31-0d83-7450-7e34cb60954e)', value: 'D' },
          { displayName: 'B ({df984366-5f31-0d83-7450-7e34cb60954e})', value: 'B' },
          { displayName: 'P ((df984366-5f31-0d83-7450-7e34cb60954e))', value: 'P' }
        ]
      }
    ],
    async run(context, guidFormat) {
      const safeGuidFormat = validateParam(guidFormat, 'enum', null, ENUMS.GUID_FORMAT, DEFAULTS.GUID_FORMAT);
      const uuid = randomUUID();
      return formatGUID(uuid, safeGuidFormat);
    }
  },

  {
    name: 'azure_request_context',
    displayName: `${DISPLAY_NAME_PREFIX} Azure Request Context`,
    description: 'Generate Azure request context header',
    args: [
      {
        displayName: 'App ID',
        description: 'Application ID (alphanumeric, dash, underscore, dot)',
        type: 'string',
        defaultValue: DEFAULTS.APP_ID
      }
    ],
    async run(context, appId) {
      const safeAppId = validateParam(appId, 'string', PATTERNS.APP_ID, null, DEFAULTS.APP_ID);
      return `appId=cid-v1:${safeAppId}`;
    }
  },

  {
    name: 'azure_client_request_id',
    displayName: `${DISPLAY_NAME_PREFIX} Azure Client Request ID`,
    description: 'Generate Azure client request ID header',
    args: [],
    async run() {
      return randomUUID();
    }
  },

  {
    name: 'azure_correlation_request_id',
    displayName: `${DISPLAY_NAME_PREFIX} Azure Correlation Request ID`,
    description: 'Generate Azure correlation request ID header',
    args: [],
    async run() {
      return randomUUID();
    }
  },

  // Jaeger Headers
  {
    name: 'jaeger_trace_id',
    displayName: `${DISPLAY_NAME_PREFIX} Jaeger Trace ID`,
    description: 'Generate Uber/Jaeger trace ID header',
    args: [],
    async run() {
      const traceId = randomHex(16);
      const spanId = randomHex(8);
      const parentId = randomHex(8);
      return `${traceId}:${spanId}:${parentId}:1`;
    }
  },

  {
    name: 'jaeger_debug_id',
    displayName: `${DISPLAY_NAME_PREFIX} Jaeger Debug ID`,
    description: 'Generate Jaeger debug ID header',
    args: [],
    async run() {
      return randomHex(16);
    }
  },

  {
    name: 'jaeger_baggage',
    displayName: `${DISPLAY_NAME_PREFIX} Jaeger Baggage`,
    description: 'Generate Jaeger baggage header',
    args: [
      {
        displayName: 'Key',
        description: 'Baggage key (alphanumeric, dash, underscore)',
        type: 'string',
        defaultValue: DEFAULTS.BAGGAGE_KEY
      },
      {
        displayName: 'Value',
        description: 'Baggage value (alphanumeric, dash, underscore)',
        type: 'string',
        defaultValue: DEFAULTS.BAGGAGE_VALUE
      }
    ],
    async run(context, key, value) {
      const safeKey = validateParam(key, 'string', PATTERNS.KEY_VALUE, null, DEFAULTS.BAGGAGE_KEY);
      const safeValue = validateParam(value, 'string', PATTERNS.KEY_VALUE, null, DEFAULTS.BAGGAGE_VALUE);
      return `${safeKey}=${safeValue}`;
    }
  },

  // Zipkin B3 Headers
  {
    name: 'zipkin_trace_id',
    displayName: `${DISPLAY_NAME_PREFIX} Zipkin B3 Trace ID`,
    description: 'Generate Zipkin B3 trace ID header',
    args: [
      {
        displayName: 'Length',
        description: 'Trace ID length in bits (64 or 128)',
        type: 'enum',
        defaultValue: DEFAULTS.TRACE_LENGTH,
        options: [
          { displayName: '64-bit', value: '64' },
          { displayName: '128-bit', value: '128' }
        ]
      }
    ],
    async run(context, length) {
      const safeLength = validateParam(length, 'enum', null, ENUMS.TRACE_LENGTH, DEFAULTS.TRACE_LENGTH);
      return safeLength === '128' ? randomHex(16) : randomHex(8);
    }
  },

  {
    name: 'zipkin_span_id',
    displayName: `${DISPLAY_NAME_PREFIX} Zipkin B3 Span ID`,
    description: 'Generate Zipkin B3 span ID header',
    args: [],
    async run() {
      return randomHex(8);
    }
  },

  {
    name: 'zipkin_parent_span_id',
    displayName: `${DISPLAY_NAME_PREFIX} Zipkin B3 Parent Span ID`,
    description: 'Generate Zipkin B3 parent span ID header',
    args: [],
    async run() {
      return randomHex(8);
    }
  },

  {
    name: 'zipkin_sampled',
    displayName: `${DISPLAY_NAME_PREFIX} Zipkin B3 Sampled`,
    description: 'Generate Zipkin B3 sampled header',
    args: [
      {
        displayName: 'Sampled',
        description: 'Whether the trace is sampled',
        type: 'boolean',
        defaultValue: DEFAULTS.SAMPLED
      }
    ],
    async run(context, sampled) {
      const isSampled = validateParam(sampled, 'boolean', null, null, DEFAULTS.SAMPLED);
      return isSampled ? '1' : '0';
    }
  },

  {
    name: 'zipkin_flags',
    displayName: `${DISPLAY_NAME_PREFIX} Zipkin B3 Flags`,
    description: 'Generate Zipkin B3 flags header',
    args: [],
    async run() {
      return '0';
    }
  },

  {
    name: 'zipkin_b3_single',
    displayName: `${DISPLAY_NAME_PREFIX} Zipkin B3 Single Header`,
    description: 'Generate Zipkin B3 single header format',
    args: [
      {
        displayName: 'Sampled',
        description: 'Whether the trace is sampled',
        type: 'boolean',
        defaultValue: DEFAULTS.SAMPLED
      }
    ],
    async run(context, sampled) {
      const traceId = randomHex(16);
      const spanId = randomHex(8);
      const isSampled = validateParam(sampled, 'boolean', null, null, DEFAULTS.SAMPLED);
      const sampledFlag = isSampled ? '1' : '0';
      return `${traceId}-${spanId}-${sampledFlag}`;
    }
  },

  // New Relic Headers
  {
    name: 'newrelic_header',
    displayName: `${DISPLAY_NAME_PREFIX} New Relic Header`,
    description: 'Generate New Relic distributed tracing header',
    args: [
      {
        displayName: 'Account ID',
        description: 'New Relic account ID (numeric)',
        type: 'string',
        defaultValue: DEFAULTS.ACCOUNT_ID
      },
      {
        displayName: 'App ID',
        description: 'Application ID (numeric)',
        type: 'string',
        defaultValue: DEFAULTS.NEW_RELIC_APP_ID
      }
    ],
    async run(context, accountId, appId) {
      const safeAccountId = validateParam(accountId, 'string', PATTERNS.NUMERIC, null, DEFAULTS.ACCOUNT_ID);
      const safeAppId = validateParam(appId, 'string', PATTERNS.NUMERIC, null, DEFAULTS.NEW_RELIC_APP_ID);
      
      const payload = {
        v: [0, 1],
        d: {
          ty: 'App',
          ac: safeAccountId,
          ap: safeAppId,
          id: randomHex(8),
          tr: randomHex(8),
          pr: 0.5,
          sa: true,
          ti: Date.now()
        }
      };
      return safeBase64(JSON.stringify(payload));
    }
  },

  {
    name: 'newrelic_id',
    displayName: `${DISPLAY_NAME_PREFIX} New Relic ID`,
    description: 'Generate New Relic ID header',
    args: [],
    async run() {
      return randomHex(8);
    }
  },

  {
    name: 'newrelic_transaction',
    displayName: `${DISPLAY_NAME_PREFIX} New Relic Transaction`,
    description: 'Generate New Relic transaction header',
    args: [],
    async run() {
      return randomHex(16);
    }
  },

  // Google Cloud Trace
  {
    name: 'gcloud_trace_context',
    displayName: `${DISPLAY_NAME_PREFIX} Google Cloud Trace Context`,
    description: 'Generate Google Cloud trace context header',
    args: [],
    async run() {
      return `${randomHex(16)}/${randomNumber()};o=1`;
    }
  },

  {
    name: 'goog_trace',
    displayName: `${DISPLAY_NAME_PREFIX} Google Trace`,
    description: 'Generate Google trace header',
    args: [],
    async run() {
      return `${randomHex(16)}/${randomNumber()}`;
    }
  },

  // CloudFlare Headers
  {
    name: 'cloudflare_ray',
    displayName: `${DISPLAY_NAME_PREFIX} CloudFlare Ray ID`,
    description: 'Generate CloudFlare Ray ID header',
    args: [],
    async run() {
      const dcs = ['DFW', 'LAX', 'ORD', 'JFK', 'LHR', 'NRT', 'SJC', 'SEA', 'MIA', 'ATL', 'BOS', 'IAD'];
      const dc = dcs[Math.floor(Math.random() * dcs.length)];
      return `${randomHex(8)}-${dc}`;
    }
  },

  {
    name: 'cloudflare_request_id',
    displayName: `${DISPLAY_NAME_PREFIX} CloudFlare Request ID`,
    description: 'Generate CloudFlare request ID header',
    args: [],
    async run() {
      return randomHex(16);
    }
  },

  // Sentry Headers
  {
    name: 'sentry_trace',
    displayName: `${DISPLAY_NAME_PREFIX} Sentry Trace`,
    description: 'Generate Sentry trace header',
    args: [
      {
        displayName: 'Sampled',
        description: 'Whether the trace is sampled',
        type: 'boolean',
        defaultValue: DEFAULTS.SAMPLED
      }
    ],
    async run(context, sampled) {
      const traceId = randomHex(16);
      const spanId = randomHex(8);
      const isSampled = validateParam(sampled, 'boolean', null, null, DEFAULTS.SAMPLED);
      const sampledFlag = isSampled ? '1' : '0';
      return `${traceId}-${spanId}-${sampledFlag}`;
    }
  },

  {
    name: 'sentry_baggage',
    displayName: `${DISPLAY_NAME_PREFIX} Sentry Baggage`,
    description: 'Generate Sentry baggage header',
    args: [
      {
        displayName: 'Environment',
        description: 'Environment name (alphanumeric, dash, underscore, dot)',
        type: 'string',
        defaultValue: DEFAULTS.ENVIRONMENT
      }
    ],
    async run(context, environment) {
      const safeEnv = validateParam(environment, 'string', PATTERNS.ENVIRONMENT_NAME, null, DEFAULTS.ENVIRONMENT);
      return `sentry-environment=${safeEnv},sentry-trace_id=${randomHex(16)}`;
    }
  },

  // Elastic APM
  {
    name: 'elastic_traceparent',
    displayName: `${DISPLAY_NAME_PREFIX} Elastic APM Traceparent`,
    description: 'Generate Elastic APM traceparent header (W3C format)',
    args: [
      {
        displayName: 'Sampled',
        description: 'Whether the trace is sampled',
        type: 'boolean',
        defaultValue: DEFAULTS.SAMPLED
      }
    ],
    async run(context, sampled) {
      const traceId = randomHex(16);
      const spanId = randomHex(8);
      const isSampled = validateParam(sampled, 'boolean', null, null, DEFAULTS.SAMPLED);
      const flags = isSampled ? '01' : '00';
      return `00-${traceId}-${spanId}-${flags}`;
    }
  },

  {
    name: 'elastic_tracestate',
    displayName: `${DISPLAY_NAME_PREFIX} Elastic APM Tracestate`,
    description: 'Generate Elastic APM tracestate header',
    args: [],
    async run() {
      return `es=s:1.0`;
    }
  },

  // Dynatrace Headers
  {
    name: 'dynatrace_header',
    displayName: `${DISPLAY_NAME_PREFIX} Dynatrace Header`,
    description: 'Generate Dynatrace tracing header',
    args: [
      {
        displayName: 'Application ID',
        description: 'Dynatrace application ID (alphanumeric, dash, underscore)',
        type: 'string',
        defaultValue: DEFAULTS.DYNATRACE_APP_ID
      }
    ],
    async run(context, appId) {
      const safeAppId = validateParam(appId, 'string', PATTERNS.APP_ID, null, DEFAULTS.DYNATRACE_APP_ID);
      const traceId = randomNumber();
      const spanId = randomNumber();
      return `FW4;${traceId};${spanId};1;${safeAppId}`;
    }
  },

  {
    name: 'dynatrace_origin',
    displayName: `${DISPLAY_NAME_PREFIX} Dynatrace Origin`,
    description: 'Generate Dynatrace origin header',
    args: [],
    async run() {
      return `dt=${randomHex(8)}`;
    }
  },

  // AppDynamics
  {
    name: 'appdynamics_header',
    displayName: `${DISPLAY_NAME_PREFIX} AppDynamics Header`,
    description: 'Generate AppDynamics singularityheader',
    args: [],
    async run() {
      return `${randomHex(8)}-${randomHex(4)}-${randomHex(4)}-${randomHex(4)}-${randomHex(12)}`;
    }
  },

  // Honeycomb
  {
    name: 'honeycomb_trace',
    displayName: `${DISPLAY_NAME_PREFIX} Honeycomb Trace`,
    description: 'Generate Honeycomb trace header',
    args: [
      {
        displayName: 'Dataset',
        description: 'Dataset name (alphanumeric, dash, underscore, dot)',
        type: 'string',
        defaultValue: DEFAULTS.DATASET
      }
    ],
    async run(context, dataset) {
      validateParam(dataset, 'string', PATTERNS.SERVICE_NAME, null, DEFAULTS.DATASET);
      return randomHex(16);
    }
  },

  {
    name: 'honeycomb_dataset',
    displayName: `${DISPLAY_NAME_PREFIX} Honeycomb Dataset`,
    description: 'Generate Honeycomb dataset header',
    args: [
      {
        displayName: 'Dataset Name',
        description: 'Name of the dataset (alphanumeric, dash, underscore, dot)',
        type: 'string',
        defaultValue: DEFAULTS.DATASET
      }
    ],
    async run(context, dataset) {
      return validateParam(dataset, 'string', PATTERNS.SERVICE_NAME, null, DEFAULTS.DATASET);
    }
  },

  {
    name: 'honeycomb_samplerate',
    displayName: `${DISPLAY_NAME_PREFIX} Honeycomb Sample Rate`,
    description: 'Generate Honeycomb sample rate header',
    args: [
      {
        displayName: 'Sample Rate',
        description: 'Sampling rate (1, 10, or 100)',
        type: 'enum',
        defaultValue: DEFAULTS.SAMPLE_RATE,
        options: [
          { displayName: '1 (100%)', value: '1' },
          { displayName: '10 (10%)', value: '10' },
          { displayName: '100 (1%)', value: '100' }
        ]
      }
    ],
    async run(context, rate) {
      return validateParam(rate, 'enum', null, ENUMS.SAMPLE_RATE, DEFAULTS.SAMPLE_RATE);
    }
  },

  // LightStep
  {
    name: 'lightstep_span_context',
    displayName: `${DISPLAY_NAME_PREFIX} LightStep Span Context`,
    description: 'Generate LightStep span context header',
    args: [],
    async run() {
      return randomHex(16);
    }
  },

  // Istio/Envoy
  {
    name: 'envoy_request_id',
    displayName: `${DISPLAY_NAME_PREFIX} Envoy Request ID`,
    description: 'Generate Envoy request ID header',
    args: [],
    async run() {
      return randomUUID();
    }
  },

  {
    name: 'envoy_original_path',
    displayName: `${DISPLAY_NAME_PREFIX} Envoy Original Path`,
    description: 'Generate Envoy original path header',
    args: [
      {
        displayName: 'Original Path',
        description: 'Original request path (valid URL path)',
        type: 'string',
        defaultValue: DEFAULTS.PATH
      }
    ],
    async run(context, path) {
      return validateParam(path, 'string', PATTERNS.PATH, null, DEFAULTS.PATH);
    }
  },

  // Tyk API Gateway Headers
  {
    name: 'tyk_trace_id',
    displayName: `${DISPLAY_NAME_PREFIX} Tyk Trace ID`,
    description: 'Generate Tyk API Gateway trace ID header with GUID format support',
    args: [
      {
        displayName: 'Format',
        description: 'ID format type',
        type: 'enum',
        defaultValue: DEFAULTS.FORMAT,
        options: [
          { displayName: 'Hexadecimal', value: 'hex' },
          { displayName: 'UUID', value: 'uuid' },
          { displayName: 'Numeric', value: 'numeric' }
        ]
      },
      {
        displayName: 'GUID Format',
        description: 'GUID format (N=no hyphens, D=hyphens, B=braces, P=parentheses)',
        type: 'enum',
        defaultValue: DEFAULTS.GUID_FORMAT,
        options: [
          { displayName: 'N (df9843665f310d8374507e34cb60954e)', value: 'N' },
          { displayName: 'D (df984366-5f31-0d83-7450-7e34cb60954e)', value: 'D' },
          { displayName: 'B ({df984366-5f31-0d83-7450-7e34cb60954e})', value: 'B' },
          { displayName: 'P ((df984366-5f31-0d83-7450-7e34cb60954e))', value: 'P' }
        ]
      }
    ],
    async run(context, format, guidFormat) {
      const safeFormat = validateParam(format, 'enum', null, ENUMS.FORMAT, DEFAULTS.FORMAT);
      const safeGuidFormat = validateParam(guidFormat, 'enum', null, ENUMS.GUID_FORMAT, DEFAULTS.GUID_FORMAT);
      
      if (safeFormat === 'uuid') {
        const uuid = randomUUID();
        return formatGUID(uuid, safeGuidFormat);
      }
      if (safeFormat === 'numeric') return randomNumber();
      return randomHex(16);
    }
  },

  {
    name: 'tyk_request_id',
    displayName: `${DISPLAY_NAME_PREFIX} Tyk Request ID`,
    description: 'Generate Tyk API Gateway request ID header',
    args: [
      {
        displayName: 'GUID Format',
        description: 'GUID format (N=no hyphens, D=hyphens, B=braces, P=parentheses)',
        type: 'enum',
        defaultValue: DEFAULTS.GUID_FORMAT,
        options: [
          { displayName: 'N (df9843665f310d8374507e34cb60954e)', value: 'N' },
          { displayName: 'D (df984366-5f31-0d83-7450-7e34cb60954e)', value: 'D' },
          { displayName: 'B ({df984366-5f31-0d83-7450-7e34cb60954e})', value: 'B' },
          { displayName: 'P ((df984366-5f31-0d83-7450-7e34cb60954e))', value: 'P' }
        ]
      }
    ],
    async run(context, guidFormat) {
      const safeGuidFormat = validateParam(guidFormat, 'enum', null, ENUMS.GUID_FORMAT, DEFAULTS.GUID_FORMAT);
      const uuid = randomUUID();
      return formatGUID(uuid, safeGuidFormat);
    }
  },

  {
    name: 'tyk_authorization',
    displayName: `${DISPLAY_NAME_PREFIX} Tyk Authorization`,
    description: 'Generate Tyk authorization header (for management API)',
    args: [
      {
        displayName: 'Secret Key',
        description: 'Tyk secret key (alphanumeric, dash, underscore)',
        type: 'string',
        defaultValue: DEFAULTS.SECRET_KEY
      }
    ],
    async run(context, secretKey) {
      return validateParam(secretKey, 'string', PATTERNS.KEY_VALUE, null, DEFAULTS.SECRET_KEY);
    }
  },

  {
    name: 'tyk_version',
    displayName: `${DISPLAY_NAME_PREFIX} Tyk API Version`,
    description: 'Generate Tyk API version header',
    args: [
      {
        displayName: 'Version',
        description: 'API version (version string like v1, v2.1)',
        type: 'string',
        defaultValue: DEFAULTS.API_VERSION
      }
    ],
    async run(context, version) {
      return validateParam(version, 'string', PATTERNS.VERSION_STRING, null, DEFAULTS.API_VERSION);
    }
  },

  {
    name: 'tyk_base_api_id',
    displayName: `${DISPLAY_NAME_PREFIX} Tyk Base API ID`,
    description: 'Generate Tyk base API ID header for versioned APIs',
    args: [],
    async run() {
      return randomHex(24);
    }
  },

  {
    name: 'tyk_session_id',
    displayName: `${DISPLAY_NAME_PREFIX} Tyk Session ID`,
    description: 'Generate Tyk session identifier',
    args: [],
    async run() {
      return 'tyk-' + randomUUID();
    }
  },

  // Snowflake ID Headers
  {
    name: 'snowflake_id',
    displayName: `${DISPLAY_NAME_PREFIX} Snowflake ID`,
    description: 'Generate a Twitter-style Snowflake ID (64-bit distributed unique identifier)',
    args: [
      {
        displayName: 'Machine ID',
        description: 'Machine identifier (0-1023)',
        type: 'number',
        defaultValue: DEFAULTS.MACHINE_ID
      },
      {
        displayName: 'Epoch Type',
        description: 'Epoch starting point',
        type: 'enum',
        defaultValue: DEFAULTS.EPOCH_TYPE,
        options: [
          { displayName: 'Twitter (Nov 4, 2010)', value: 'twitter' },
          { displayName: 'Discord (Jan 1, 2015)', value: 'discord' },
          { displayName: 'Unix Epoch (Jan 1, 1970)', value: 'unix' },
          { displayName: 'Custom', value: 'custom' }
        ]
      },
      {
        displayName: 'Custom Epoch (ms)',
        description: 'Custom epoch time in milliseconds',
        type: 'number',
        defaultValue: DEFAULTS.CUSTOM_EPOCH
      }
    ],
    async run(context, machineId, epochType, customEpoch) {
      const safeMachineId = validateParam(machineId, 'number', null, null, DEFAULTS.MACHINE_ID);
      const safeEpochType = validateParam(epochType, 'enum', null, ENUMS.EPOCH_TYPE, DEFAULTS.EPOCH_TYPE);
      const safeCustomEpoch = validateParam(customEpoch, 'number', null, null, DEFAULTS.CUSTOM_EPOCH);
      
      let epoch;
      switch (safeEpochType) {
        case 'twitter': epoch = 1288834974657; break;
        case 'discord': epoch = 1420070400000; break;
        case 'unix': epoch = 0; break;
        case 'custom': epoch = safeCustomEpoch; break;
        default: epoch = 1288834974657;
      }
      return generateSnowflake(epoch, safeMachineId);
    }
  },

  {
    name: 'twitter_snowflake',
    displayName: `${DISPLAY_NAME_PREFIX} Twitter Snowflake`,
    description: 'Generate a Twitter Snowflake ID using Twitter\'s epoch',
    args: [
      {
        displayName: 'Machine ID',
        description: 'Machine identifier (0-1023)',
        type: 'number',
        defaultValue: DEFAULTS.MACHINE_ID
      }
    ],
    async run(context, machineId) {
      const safeMachineId = validateParam(machineId, 'number', null, null, DEFAULTS.MACHINE_ID);
      return generateSnowflake(1288834974657, safeMachineId);
    }
  },

  {
    name: 'discord_snowflake',
    displayName: `${DISPLAY_NAME_PREFIX} Discord Snowflake`,
    description: 'Generate a Discord Snowflake ID using Discord\'s epoch',
    args: [
      {
        displayName: 'Machine ID',
        description: 'Machine identifier (0-1023)',
        type: 'number',
        defaultValue: DEFAULTS.MACHINE_ID
      }
    ],
    async run(context, machineId) {
      const safeMachineId = validateParam(machineId, 'number', null, null, DEFAULTS.MACHINE_ID);
      return generateSnowflake(1420070400000, safeMachineId);
    }
  },

  {
    name: 'custom_snowflake',
    displayName: `${DISPLAY_NAME_PREFIX} Custom Snowflake ID`,
    description: 'Generate a custom Snowflake ID with configurable parameters',
    args: [
      {
        displayName: 'Epoch Start (ms)',
        description: 'Starting epoch time in milliseconds',
        type: 'number',
        defaultValue: 1609459200000
      },
      {
        displayName: 'Machine ID',
        description: 'Machine identifier (0-1023)',
        type: 'number',
        defaultValue: DEFAULTS.MACHINE_ID
      }
    ],
    async run(context, epochStart, machineId) {
      const safeEpochStart = validateParam(epochStart, 'number', null, null, 1609459200000);
      const safeMachineId = validateParam(machineId, 'number', null, null, DEFAULTS.MACHINE_ID);
      return generateSnowflake(safeEpochStart, safeMachineId);
    }
  },

  // Generic Correlation Headers
  {
    name: 'correlation_id',
    displayName: `${DISPLAY_NAME_PREFIX} Correlation ID`,
    description: 'Generate a correlation ID header',
    args: [
      {
        displayName: 'Format',
        description: 'ID format type',
        type: 'enum',
        defaultValue: DEFAULTS.CORRELATION_FORMAT,
        options: [
          { displayName: 'UUID', value: 'uuid' },
          { displayName: 'Hex (64-bit)', value: 'hex64' },
          { displayName: 'Hex (128-bit)', value: 'hex128' },
          { displayName: 'Numeric', value: 'numeric' }
        ]
      },
      {
        displayName: 'GUID Format',
        description: 'GUID format when UUID selected (N=no hyphens, D=hyphens, B=braces, P=parentheses)',
        type: 'enum',
        defaultValue: DEFAULTS.GUID_FORMAT,
        options: [
          { displayName: 'N (df9843665f310d8374507e34cb60954e)', value: 'N' },
          { displayName: 'D (df984366-5f31-0d83-7450-7e34cb60954e)', value: 'D' },
          { displayName: 'B ({df984366-5f31-0d83-7450-7e34cb60954e})', value: 'B' },
          { displayName: 'P ((df984366-5f31-0d83-7450-7e34cb60954e))', value: 'P' }
        ]
      }
    ],
    async run(context, format, guidFormat) {
      const safeFormat = validateParam(format, 'enum', null, ENUMS.CORRELATION_FORMAT, DEFAULTS.CORRELATION_FORMAT);
      const safeGuidFormat = validateParam(guidFormat, 'enum', null, ENUMS.GUID_FORMAT, DEFAULTS.GUID_FORMAT);
      
      switch (safeFormat) {
        case 'uuid': 
          const uuid = randomUUID();
          return formatGUID(uuid, safeGuidFormat);
        case 'hex64': return randomHex(8);
        case 'hex128': return randomHex(16);
        case 'numeric': return randomNumber();
        default: 
          const defaultUuid = randomUUID();
          return formatGUID(defaultUuid, safeGuidFormat);
      }
    }
  },

  {
    name: 'trace_id',
    displayName: `${DISPLAY_NAME_PREFIX} Generic Trace ID`,
    description: 'Generate a generic trace ID header',
    args: [],
    async run() {
      return randomHex(16);
    }
  },

  {
    name: 'span_id',
    displayName: `${DISPLAY_NAME_PREFIX} Generic Span ID`,
    description: 'Generate a generic span ID header',
    args: [],
    async run() {
      return randomHex(8);
    }
  },

  {
    name: 'parent_id',
    displayName: `${DISPLAY_NAME_PREFIX} Generic Parent ID`,
    description: 'Generate a generic parent ID header',
    args: [],
    async run() {
      return randomHex(8);
    }
  },

  {
    name: 'operation_id',
    displayName: `${DISPLAY_NAME_PREFIX} Operation ID`,
    description: 'Generate an operation ID header',
    args: [
      {
        displayName: 'GUID Format',
        description: 'GUID format (N=no hyphens, D=hyphens, B=braces, P=parentheses)',
        type: 'enum',
        defaultValue: DEFAULTS.GUID_FORMAT,
        options: [
          { displayName: 'N (df9843665f310d8374507e34cb60954e)', value: 'N' },
          { displayName: 'D (df984366-5f31-0d83-7450-7e34cb60954e)', value: 'D' },
          { displayName: 'B ({df984366-5f31-0d83-7450-7e34cb60954e})', value: 'B' },
          { displayName: 'P ((df984366-5f31-0d83-7450-7e34cb60954e))', value: 'P' }
        ]
      }
    ],
    async run(context, guidFormat) {
      const safeGuidFormat = validateParam(guidFormat, 'enum', null, ENUMS.GUID_FORMAT, DEFAULTS.GUID_FORMAT);
      const uuid = randomUUID();
      return formatGUID(uuid, safeGuidFormat);
    }
  },

  {
    name: 'session_id',
    displayName: `${DISPLAY_NAME_PREFIX} Session ID`,
    description: 'Generate a session ID header',
    args: [],
    async run() {
      return 'sess_' + randomHex(16);
    }
  },

  {
    name: 'user_id',
    displayName: `${DISPLAY_NAME_PREFIX} User ID`,
    description: 'Generate a user ID header',
    args: [
      {
        displayName: 'Format',
        description: 'ID format type',
        type: 'enum',
        defaultValue: DEFAULTS.USER_FORMAT,
        options: [
          { displayName: 'Numeric', value: 'numeric' },
          { displayName: 'UUID', value: 'uuid' },
          { displayName: 'Hex', value: 'hex' }
        ]
      },
      {
        displayName: 'GUID Format',
        description: 'GUID format when UUID selected (N=no hyphens, D=hyphens, B=braces, P=parentheses)',
        type: 'enum',
        defaultValue: DEFAULTS.GUID_FORMAT,
        options: [
          { displayName: 'N (df9843665f310d8374507e34cb60954e)', value: 'N' },
          { displayName: 'D (df984366-5f31-0d83-7450-7e34cb60954e)', value: 'D' },
          { displayName: 'B ({df984366-5f31-0d83-7450-7e34cb60954e})', value: 'B' },
          { displayName: 'P ((df984366-5f31-0d83-7450-7e34cb60954e))', value: 'P' }
        ]
      }
    ],
    async run(context, format, guidFormat) {
      const safeFormat = validateParam(format, 'enum', null, ENUMS.USER_FORMAT, DEFAULTS.USER_FORMAT);
      const safeGuidFormat = validateParam(guidFormat, 'enum', null, ENUMS.GUID_FORMAT, DEFAULTS.GUID_FORMAT);
      
      switch (safeFormat) {
        case 'numeric': return Math.floor(Math.random() * 1000000).toString();
        case 'uuid': 
          const uuid = randomUUID();
          return formatGUID(uuid, safeGuidFormat);
        case 'hex': return randomHex(8);
        default: return Math.floor(Math.random() * 1000000).toString();
      }
    }
  },

  {
    name: 'tenant_id',
    displayName: `${DISPLAY_NAME_PREFIX} Tenant ID`,
    description: 'Generate a tenant ID header',
    args: [],
    async run() {
      return 'tenant_' + randomHex(8);
    }
  },

  {
    name: 'application_id',
    displayName: `${DISPLAY_NAME_PREFIX} Application ID`,
    description: 'Generate an application ID header',
    args: [],
    async run() {
      return 'app_' + randomHex(12);
    }
  },

  {
    name: 'service_id',
    displayName: `${DISPLAY_NAME_PREFIX} Service ID`,
    description: 'Generate a service ID header',
    args: [],
    async run() {
      return 'svc_' + randomHex(10);
    }
  },

  // Custom Trace Header Builder
  {
    name: 'custom_trace_header',
    displayName: `${DISPLAY_NAME_PREFIX} Custom Trace Header`,
    description: 'Generate a custom trace header with configurable format',
    args: [
      {
        displayName: 'Format',
        description: 'Header format template (use {traceId}, {spanId}, {timestamp})',
        type: 'string',
        defaultValue: DEFAULTS.TRACE_FORMAT
      },
      {
        displayName: 'Trace ID Length',
        description: 'Trace ID length in bits',
        type: 'enum',
        defaultValue: DEFAULTS.TRACE_LENGTH,
        options: [
          { displayName: '64-bit', value: '64' },
          { displayName: '128-bit', value: '128' }
        ]
      }
    ],
    async run(context, format, traceIdLength) {
      const safeFormat = validateParam(format, 'string', PATTERNS.TRACE_FORMAT, null, DEFAULTS.TRACE_FORMAT);
      const safeLength = validateParam(traceIdLength, 'enum', null, ENUMS.TRACE_LENGTH, DEFAULTS.TRACE_LENGTH);
      
      const traceId = safeLength === '128' ? randomHex(16) : randomHex(8);
      const spanId = randomHex(8);
      const ts = timestamp();
      
      return safeFormat
        .replace(/{traceId}/g, traceId)
        .replace(/{spanId}/g, spanId)
        .replace(/{timestamp}/g, ts);
    }
  }
];