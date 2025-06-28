const crypto = require('crypto');

// Helper functions for generating various ID formats using crypto
function generateHexId(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

function generateTraceId128() {
  return generateHexId(16); // 128-bit = 16 bytes
}

function generateTraceId64() {
  return generateHexId(8); // 64-bit = 8 bytes
}

function generateSpanId() {
  return generateHexId(8); // 64-bit = 8 bytes
}

function generateNumericId() {
  // Generate a random 53-bit integer (max safe integer in JavaScript)
  const bytes = crypto.randomBytes(7); // 56 bits, we'll mask to 53
  let result = 0;
  for (let i = 0; i < 7; i++) {
    result = result * 256 + bytes[i];
  }
  // Ensure it's within safe integer range
  return (result & 0x1FFFFFFFFFFFFF).toString();
}

function generateUUID() {
  // Generate UUID v4 using crypto
  const bytes = crypto.randomBytes(16);
  
  // Set version (4) and variant bits
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 10
  
  const hex = bytes.toString('hex');
  return [
    hex.substring(0, 8),
    hex.substring(8, 12),
    hex.substring(12, 16),
    hex.substring(16, 20),
    hex.substring(20, 32)
  ].join('-');
}

function generateTimestamp() {
  return Math.floor(Date.now() / 1000).toString();
}

function generateRandomInt(min = 0, max = 1) {
  const range = max - min + 1;
  const bytes = crypto.randomBytes(4);
  const randomValue = bytes.readUInt32BE(0);
  return min + (randomValue % range);
}

// Snowflake ID generation
let snowflakeSequence = 0;
let lastSnowflakeTimestamp = 0;

function generateSnowflakeId(epochStart = 1288834974657, machineId = 0) {
  // Snowflake format: 1 bit sign + 41 bits timestamp + 10 bits machine + 12 bits sequence
  
  // Validate inputs
  if (machineId < 0 || machineId > 1023) {
    machineId = generateRandomInt(0, 1023); // 10 bits max (2^10 - 1 = 1023)
  }
  
  let timestamp = Date.now() - epochStart;
  
  // Handle clock going backwards or same millisecond
  if (timestamp < lastSnowflakeTimestamp) {
    throw new Error('Clock went backwards. Refusing to generate id');
  }
  
  if (timestamp === lastSnowflakeTimestamp) {
    snowflakeSequence = (snowflakeSequence + 1) & 4095; // 12 bits max (2^12 - 1 = 4095)
    if (snowflakeSequence === 0) {
      // Sequence exhausted, wait for next millisecond
      while (timestamp <= lastSnowflakeTimestamp) {
        timestamp = Date.now() - epochStart;
      }
    }
  } else {
    snowflakeSequence = 0;
  }
  
  lastSnowflakeTimestamp = timestamp;
  
  // Construct the Snowflake ID
  // JavaScript's bitwise operations work on 32-bit signed integers
  // So we need to be careful with 64-bit operations
  const id = (BigInt(timestamp) << 22n) | (BigInt(machineId) << 12n) | BigInt(snowflakeSequence);
  
  return id.toString();
}

// Template tags
module.exports.templateTags = [
  // W3C Trace Context / OpenTelemetry
  {
    name: 'traceparent',
    displayName: 'W3C Traceparent',
    description: 'Generate a W3C traceparent header for OpenTelemetry distributed tracing',
    args: [
      {
        displayName: 'Version',
        description: 'Trace context version (usually 00)',
        type: 'string',
        defaultValue: '00'
      },
      {
        displayName: 'Sampled',
        description: 'Whether this trace is sampled',
        type: 'boolean',
        defaultValue: true
      }
    ],
    async run(context, version, sampled) {
      const traceId = generateTraceId128();
      const spanId = generateSpanId();
      const flags = sampled ? '01' : '00';
      return `${version}-${traceId}-${spanId}-${flags}`;
    }
  },

  // Datadog APM Headers
  {
    name: 'datadog-trace-id',
    displayName: 'Datadog Trace ID',
    description: 'Generate a Datadog trace ID header',
    args: [],
    async run() {
      return generateNumericId();
    }
  },
  {
    name: 'datadog-parent-id',
    displayName: 'Datadog Parent ID',
    description: 'Generate a Datadog parent/span ID header',
    args: [],
    async run() {
      return generateNumericId();
    }
  },
  {
    name: 'datadog-sampling-priority',
    displayName: 'Datadog Sampling Priority',
    description: 'Generate Datadog sampling priority header',
    args: [
      {
        displayName: 'Priority',
        description: 'Sampling priority level',
        type: 'enum',
        defaultValue: '1',
        options: [
          { displayName: 'Auto Reject (-1)', value: '-1' },
          { displayName: 'Auto Keep (0)', value: '0' },
          { displayName: 'User Keep (1)', value: '1' },
          { displayName: 'User Reject (2)', value: '2' }
        ]
      }
    ],
    async run(context, priority) {
      return priority;
    }
  },
  {
    name: 'datadog-origin',
    displayName: 'Datadog Origin',
    description: 'Generate Datadog origin header',
    args: [
      {
        displayName: 'Origin',
        description: 'Origin of the trace',
        type: 'string',
        defaultValue: 'synthetics'
      }
    ],
    async run(context, origin) {
      return origin;
    }
  },

  // AWS X-Ray Headers
  {
    name: 'aws-trace-id',
    displayName: 'AWS X-Ray Trace ID',
    description: 'Generate AWS X-Ray trace ID header',
    args: [],
    async run() {
      const timestamp = Math.floor(Date.now() / 1000).toString(16);
      const randomPart = generateHexId(12); // 96 bits
      return `Root=1-${timestamp}-${randomPart}`;
    }
  },
  {
    name: 'aws-request-id',
    displayName: 'AWS Request ID',
    description: 'Generate AWS request ID header',
    args: [],
    async run() {
      return generateUUID();
    }
  },

  // Azure Application Insights Headers
  {
    name: 'azure-request-id',
    displayName: 'Azure Request ID',
    description: 'Generate Azure request ID header',
    args: [],
    async run() {
      return generateUUID();
    }
  },
  {
    name: 'azure-request-context',
    displayName: 'Azure Request Context',
    description: 'Generate Azure request context header',
    args: [
      {
        displayName: 'App ID',
        description: 'Application ID',
        type: 'string',
        defaultValue: 'unknown'
      }
    ],
    async run(context, appId) {
      return `appId=cid-v1:${appId}`;
    }
  },

  // Jaeger Headers
  {
    name: 'jaeger-trace-id',
    displayName: 'Jaeger Trace ID',
    description: 'Generate Uber/Jaeger trace ID header',
    args: [],
    async run() {
      const traceId = generateTraceId128();
      const spanId = generateSpanId();
      const parentSpanId = generateSpanId();
      const flags = '1'; // sampled
      return `${traceId}:${spanId}:${parentSpanId}:${flags}`;
    }
  },

  // Zipkin B3 Headers
  {
    name: 'zipkin-trace-id',
    displayName: 'Zipkin B3 Trace ID',
    description: 'Generate Zipkin B3 trace ID header',
    args: [
      {
        displayName: 'Length',
        description: 'Trace ID length',
        type: 'enum',
        defaultValue: '128',
        options: [
          { displayName: '64-bit', value: '64' },
          { displayName: '128-bit', value: '128' }
        ]
      }
    ],
    async run(context, length) {
      return length === '128' ? generateTraceId128() : generateTraceId64();
    }
  },
  {
    name: 'zipkin-span-id',
    displayName: 'Zipkin B3 Span ID',
    description: 'Generate Zipkin B3 span ID header',
    args: [],
    async run() {
      return generateSpanId();
    }
  },
  {
    name: 'zipkin-b3-single',
    displayName: 'Zipkin B3 Single Header',
    description: 'Generate Zipkin B3 single header format',
    args: [
      {
        displayName: 'Sampled',
        description: 'Whether this trace is sampled',
        type: 'boolean',
        defaultValue: true
      }
    ],
    async run(context, sampled) {
      const traceId = generateTraceId128();
      const spanId = generateSpanId();
      const sampledFlag = sampled ? '1' : '0';
      return `${traceId}-${spanId}-${sampledFlag}`;
    }
  },

  // New Relic Headers
  {
    name: 'newrelic-header',
    displayName: 'New Relic Header',
    description: 'Generate New Relic distributed tracing header',
    args: [
      {
        displayName: 'Account ID',
        description: 'New Relic account ID',
        type: 'string',
        defaultValue: '1234567'
      },
      {
        displayName: 'App ID',
        description: 'New Relic application ID',
        type: 'string',
        defaultValue: '7654321'
      }
    ],
    async run(context, accountId, appId) {
      const traceId = generateTraceId64();
      const spanId = generateSpanId();
      const timestamp = Date.now();
      
      const payload = {
        v: [0, 1],
        d: {
          ty: 'App',
          ac: accountId,
          ap: appId,
          id: spanId,
          tr: traceId,
          pr: 0.5,
          sa: true,
          ti: timestamp
        }
      };
      
      return Buffer.from(JSON.stringify(payload)).toString('base64');
    }
  },

  // Google Cloud Trace
  {
    name: 'gcloud-trace-context',
    displayName: 'Google Cloud Trace Context',
    description: 'Generate Google Cloud trace context header',
    args: [],
    async run() {
      const traceId = generateTraceId128();
      const spanId = generateNumericId();
      return `${traceId}/${spanId};o=1`;
    }
  },

  // CloudFlare Headers
  {
    name: 'cloudflare-ray',
    displayName: 'CloudFlare Ray ID',
    description: 'Generate CloudFlare Ray ID header',
    args: [],
    async run() {
      const datacenters = ['DFW', 'LAX', 'ORD', 'JFK', 'LHR', 'NRT', 'SJC', 'SEA', 'MIA', 'ATL'];
      const dcIndex = generateRandomInt(0, datacenters.length - 1);
      const rayId = generateHexId(8) + '-' + datacenters[dcIndex];
      return rayId;
    }
  },

  // Generic Correlation Headers
  {
    name: 'correlation-id',
    displayName: 'Correlation ID',
    description: 'Generate a correlation ID header',
    args: [
      {
        displayName: 'Format',
        description: 'ID format to generate',
        type: 'enum',
        defaultValue: 'uuid',
        options: [
          { displayName: 'UUID', value: 'uuid' },
          { displayName: 'Hex (64-bit)', value: 'hex64' },
          { displayName: 'Hex (128-bit)', value: 'hex128' },
          { displayName: 'Numeric', value: 'numeric' }
        ]
      }
    ],
    async run(context, format) {
      switch (format) {
        case 'uuid':
          return generateUUID();
        case 'hex64':
          return generateTraceId64();
        case 'hex128':
          return generateTraceId128();
        case 'numeric':
          return generateNumericId();
        default:
          return generateUUID();
      }
    }
  },

  // Sentry Headers
  {
    name: 'sentry-trace',
    displayName: 'Sentry Trace',
    description: 'Generate Sentry trace header',
    args: [
      {
        displayName: 'Sampled',
        description: 'Whether this trace is sampled',
        type: 'boolean',
        defaultValue: true
      }
    ],
    async run(context, sampled) {
      const traceId = generateHexId(16); // 32 chars
      const spanId = generateHexId(8); // 16 chars
      const sampledFlag = sampled ? '1' : '0';
      return `${traceId}-${spanId}-${sampledFlag}`;
    }
  },

  // Elastic APM
  {
    name: 'elastic-traceparent',
    displayName: 'Elastic APM Traceparent',
    description: 'Generate Elastic APM traceparent header (W3C format)',
    args: [
      {
        displayName: 'Sampled',
        description: 'Whether this trace is sampled',
        type: 'boolean',
        defaultValue: true
      }
    ],
    async run(context, sampled) {
      const traceId = generateTraceId128();
      const spanId = generateSpanId();
      const flags = sampled ? '01' : '00';
      return `00-${traceId}-${spanId}-${flags}`;
    }
  },

  // Dynatrace Headers
  {
    name: 'dynatrace-header',
    displayName: 'Dynatrace Header',
    description: 'Generate Dynatrace tracing header',
    args: [
      {
        displayName: 'Application ID',
        description: 'Dynatrace application ID',
        type: 'string',
        defaultValue: 'APPLICATION-12345'
      }
    ],
    async run(context, appId) {
      const traceId = generateNumericId();
      const spanId = generateNumericId();
      return `FW4;${traceId};${spanId};1;${appId}`;
    }
  },

  // Tyk API Gateway Headers
  {
    name: 'tyk-trace-id',
    displayName: 'Tyk Trace ID',
    description: 'Generate Tyk API Gateway trace ID header',
    args: [
      {
        displayName: 'Format',
        description: 'Trace ID format',
        type: 'enum',
        defaultValue: 'hex',
        options: [
          { displayName: 'Hexadecimal', value: 'hex' },
          { displayName: 'UUID', value: 'uuid' },
          { displayName: 'Numeric', value: 'numeric' }
        ]
      }
    ],
    async run(context, format) {
      switch (format) {
        case 'hex':
          return generateTraceId128();
        case 'uuid':
          return generateUUID();
        case 'numeric':
          return generateNumericId();
        default:
          return generateTraceId128();
      }
    }
  },
  {
    name: 'tyk-request-id',
    displayName: 'Tyk Request ID',
    description: 'Generate Tyk API Gateway request ID header',
    args: [],
    async run() {
      return generateUUID();
    }
  },
  {
    name: 'tyk-authorization',
    displayName: 'Tyk Authorization',
    description: 'Generate Tyk authorization header (for management API)',
    args: [
      {
        displayName: 'Secret Key',
        description: 'Tyk secret key for management API',
        type: 'string',
        defaultValue: 'your-tyk-secret-key'
      }
    ],
    async run(context, secretKey) {
      return secretKey;
    }
  },
  {
    name: 'tyk-version',
    displayName: 'Tyk API Version',
    description: 'Generate Tyk API version header',
    args: [
      {
        displayName: 'Version',
        description: 'API version identifier',
        type: 'string',
        defaultValue: 'v1'
      }
    ],
    async run(context, version) {
      return version;
    }
  },
  {
    name: 'tyk-base-api-id',
    displayName: 'Tyk Base API ID',
    description: 'Generate Tyk base API ID header for versioned APIs',
    args: [],
    async run() {
      return generateHexId(16) + generateHexId(8); // 24 bytes total
    }
  },
  {
    name: 'tyk-session-id',
    displayName: 'Tyk Session ID',
    description: 'Generate Tyk session identifier',
    args: [],
    async run() {
      return 'tyk-' + generateUUID();
    }
  },

  // Snowflake ID Headers
  {
    name: 'snowflake-id',
    displayName: 'Snowflake ID',
    description: 'Generate a Twitter-style Snowflake ID (64-bit distributed unique identifier)',
    args: [
      {
        displayName: 'Machine ID',
        description: 'Machine/Worker ID (0-1023)',
        type: 'number',
        defaultValue: 0
      },
      {
        displayName: 'Epoch Type',
        description: 'Choose the epoch to use for timestamp calculation',
        type: 'enum',
        defaultValue: 'twitter',
        options: [
          { displayName: 'Twitter (Nov 4, 2010)', value: 'twitter' },
          { displayName: 'Discord (Jan 1, 2015)', value: 'discord' },
          { displayName: 'Unix Epoch (Jan 1, 1970)', value: 'unix' },
          { displayName: 'Custom', value: 'custom' }
        ]
      },
      {
        displayName: 'Custom Epoch (ms)',
        description: 'Custom epoch timestamp in milliseconds (only used if Epoch Type is Custom)',
        type: 'number',
        defaultValue: 1288834974657
      }
    ],
    async run(context, machineId, epochType, customEpoch) {
      let epochStart;
      switch (epochType) {
        case 'twitter':
          epochStart = 1288834974657; // Nov 4, 2010, 01:42:54 UTC
          break;
        case 'discord':
          epochStart = 1420070400000; // Jan 1, 2015, 00:00:00 UTC
          break;
        case 'unix':
          epochStart = 0; // Jan 1, 1970, 00:00:00 UTC
          break;
        case 'custom':
          epochStart = customEpoch;
          break;
        default:
          epochStart = 1288834974657;
      }
      
      return generateSnowflakeId(epochStart, machineId);
    }
  },
  {
    name: 'twitter-snowflake',
    displayName: 'Twitter Snowflake',
    description: 'Generate a Twitter Snowflake ID using Twitter\'s epoch',
    args: [
      {
        displayName: 'Machine ID',
        description: 'Machine/Worker ID (0-1023)',
        type: 'number',
        defaultValue: 0
      }
    ],
    async run(context, machineId) {
      return generateSnowflakeId(1288834974657, machineId); // Twitter epoch
    }
  },
  {
    name: 'discord-snowflake',
    displayName: 'Discord Snowflake',
    description: 'Generate a Discord Snowflake ID using Discord\'s epoch',
    args: [
      {
        displayName: 'Machine ID',
        description: 'Machine/Worker ID (0-1023)',
        type: 'number',
        defaultValue: 0
      }
    ],
    async run(context, machineId) {
      return generateSnowflakeId(1420070400000, machineId); // Discord epoch
    }
  },
  {
    name: 'custom-snowflake',
    displayName: 'Custom Snowflake ID',
    description: 'Generate a custom Snowflake ID with configurable parameters',
    args: [
      {
        displayName: 'Epoch Start (ms)',
        description: 'Custom epoch timestamp in milliseconds',
        type: 'number',
        defaultValue: 1609459200000 // Jan 1, 2021
      },
      {
        displayName: 'Machine ID',
        description: 'Machine/Worker ID (0-1023)',
        type: 'number',
        defaultValue: 0
      }
    ],
    async run(context, epochStart, machineId) {
      return generateSnowflakeId(epochStart, machineId);
    }
  },

  // Custom/Generic Headers
  {
    name: 'custom-trace-header',
    displayName: 'Custom Trace Header',
    description: 'Generate a custom trace header with configurable format',
    args: [
      {
        displayName: 'Format',
        description: 'Header format template (use {traceId}, {spanId}, {timestamp})',
        type: 'string',
        defaultValue: '{traceId}-{spanId}'
      },
      {
        displayName: 'Trace ID Length',
        description: 'Length of trace ID in bits',
        type: 'enum',
        defaultValue: '128',
        options: [
          { displayName: '64-bit', value: '64' },
          { displayName: '128-bit', value: '128' }
        ]
      }
    ],
    async run(context, format, traceIdLength) {
      const traceId = traceIdLength === '128' ? generateTraceId128() : generateTraceId64();
      const spanId = generateSpanId();
      const timestamp = generateTimestamp();
      
      return format
        .replace(/{traceId}/g, traceId)
        .replace(/{spanId}/g, spanId)
        .replace(/{timestamp}/g, timestamp);
    }
  }
];