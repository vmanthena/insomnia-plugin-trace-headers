const crypto = require('crypto');

// Helper functions for generating various ID formats
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

// Complete template tags with proper naming (no hyphens!)
module.exports.templateTags = [
  // W3C Trace Context / OpenTelemetry
  {
    name: 'traceparent',
    displayName: 'Trace Headers:W3C Traceparent',
    description: 'Generate W3C traceparent header for OpenTelemetry distributed tracing',
    args: [
      {
        displayName: 'Trace Headers:Version',
        type: 'string',
        defaultValue: '00'
      },
      {
        displayName: 'Trace Headers:Sampled',
        type: 'boolean',
        defaultValue: true
      }
    ],
    run(context, version, sampled) {
      const traceId = randomHex(16);
      const spanId = randomHex(8);
      const flags = sampled ? '01' : '00';
      return `${version}-${traceId}-${spanId}-${flags}`;
    }
  },

  {
    name: 'tracestate',
    displayName: 'Trace Headers:W3C Tracestate',
    description: 'Generate W3C tracestate header',
    args: [
      {
        displayName: 'Trace Headers:Vendor Key',
        type: 'string',
        defaultValue: 'vendor'
      },
      {
        displayName: 'Trace Headers:Vendor Value',
        type: 'string',
        defaultValue: 'value'
      }
    ],
    run(context, key, value) {
      return `${key}=${value}`;
    }
  },

  // Datadog APM Headers
  {
    name: 'datadog_trace_id',
    displayName: 'Trace Headers:Datadog Trace ID',
    description: 'Generate Datadog trace ID header',
    args: [],
    run() {
      return randomNumber();
    }
  },

  {
    name: 'datadog_parent_id',
    displayName: 'Trace Headers:Datadog Parent ID',
    description: 'Generate Datadog parent/span ID header',
    args: [],
    run() {
      return randomNumber();
    }
  },

  {
    name: 'datadog_sampling_priority',
    displayName: 'Trace Headers:Datadog Sampling Priority',
    description: 'Generate Datadog sampling priority header',
    args: [
      {
        displayName: 'Trace Headers:Priority',
        type: 'enum',
        defaultValue: '1',
        options: [
          { displayName: 'Trace Headers:Auto Reject (-1)', value: '-1' },
          { displayName: 'Trace Headers:Auto Keep (0)', value: '0' },
          { displayName: 'Trace Headers:User Keep (1)', value: '1' },
          { displayName: 'Trace Headers:User Reject (2)', value: '2' }
        ]
      }
    ],
    run(context, priority) {
      return priority;
    }
  },

  {
    name: 'datadog_origin',
    displayName: 'Trace Headers:Datadog Origin',
    description: 'Generate Datadog origin header',
    args: [
      {
        displayName: 'Trace Headers:Origin',
        type: 'string',
        defaultValue: 'synthetics'
      }
    ],
    run(context, origin) {
      return origin;
    }
  },

  {
    name: 'datadog_tags',
    displayName: 'Trace Headers:Datadog Tags',
    description: 'Generate Datadog tags header',
    args: [
      {
        displayName: 'Trace Headers:Environment',
        type: 'string',
        defaultValue: 'production'
      },
      {
        displayName: 'Trace Headers:Service',
        type: 'string',
        defaultValue: 'api'
      }
    ],
    run(context, env, service) {
      return `_dd.p.env=${env},_dd.p.service=${service}`;
    }
  },

  // AWS X-Ray Headers
  {
    name: 'aws_trace_id',
    displayName: 'Trace Headers:AWS X-Ray Trace ID',
    description: 'Generate AWS X-Ray trace ID header',
    args: [],
    run() {
      const ts = Math.floor(Date.now() / 1000).toString(16);
      const random = randomHex(12);
      return `Root=1-${ts}-${random}`;
    }
  },

  {
    name: 'aws_request_id',
    displayName: 'Trace Headers:AWS Request ID',
    description: 'Generate AWS request ID header',
    args: [],
    run() {
      return randomUUID();
    }
  },

  {
    name: 'aws_cf_id',
    displayName: 'Trace Headers:AWS CloudFront ID',
    description: 'Generate AWS CloudFront ID header',
    args: [],
    run() {
      return randomHex(28) + '==';
    }
  },

  {
    name: 'aws_id_2',
    displayName: 'Trace Headers:AWS ID 2',
    description: 'Generate AWS x-amz-id-2 header',
    args: [],
    run() {
      return randomHex(32) + '/abcdef+123456=';
    }
  },

  // Azure Application Insights Headers
  {
    name: 'azure_request_id',
    displayName: 'Trace Headers:Azure Request ID',
    description: 'Generate Azure request ID header',
    args: [],
    run() {
      return randomUUID();
    }
  },

  {
    name: 'azure_request_context',
    displayName: 'Trace Headers:Azure Request Context',
    description: 'Generate Azure request context header',
    args: [
      {
        displayName: 'Trace Headers:App ID',
        type: 'string',
        defaultValue: 'unknown'
      }
    ],
    run(context, appId) {
      return `appId=cid-v1:${appId}`;
    }
  },

  {
    name: 'azure_client_request_id',
    displayName: 'Trace Headers:Azure Client Request ID',
    description: 'Generate Azure client request ID header',
    args: [],
    run() {
      return randomUUID();
    }
  },

  {
    name: 'azure_correlation_request_id',
    displayName: 'Trace Headers:Azure Correlation Request ID',
    description: 'Generate Azure correlation request ID header',
    args: [],
    run() {
      return randomUUID();
    }
  },

  // Jaeger Headers
  {
    name: 'jaeger_trace_id',
    displayName: 'Trace Headers:Jaeger Trace ID',
    description: 'Generate Uber/Jaeger trace ID header',
    args: [],
    run() {
      const traceId = randomHex(16);
      const spanId = randomHex(8);
      const parentId = randomHex(8);
      return `${traceId}:${spanId}:${parentId}:1`;
    }
  },

  {
    name: 'jaeger_debug_id',
    displayName: 'Trace Headers:Jaeger Debug ID',
    description: 'Generate Jaeger debug ID header',
    args: [],
    run() {
      return randomHex(16);
    }
  },

  {
    name: 'jaeger_baggage',
    displayName: 'Trace Headers:Jaeger Baggage',
    description: 'Generate Jaeger baggage header',
    args: [
      {
        displayName: 'Trace Headers:Key',
        type: 'string',
        defaultValue: 'userid'
      },
      {
        displayName: 'Trace Headers:Value',
        type: 'string',
        defaultValue: '12345'
      }
    ],
    run(context, key, value) {
      return `${key}=${value}`;
    }
  },

  // Zipkin B3 Headers
  {
    name: 'zipkin_trace_id',
    displayName: 'Trace Headers:Zipkin B3 Trace ID',
    description: 'Generate Zipkin B3 trace ID header',
    args: [
      {
        displayName: 'Trace Headers:Length',
        type: 'enum',
        defaultValue: '128',
        options: [
          { displayName: 'Trace Headers:64-bit', value: '64' },
          { displayName: 'Trace Headers:128-bit', value: '128' }
        ]
      }
    ],
    run(context, length) {
      return length === '128' ? randomHex(16) : randomHex(8);
    }
  },

  {
    name: 'zipkin_span_id',
    displayName: 'Trace Headers:Zipkin B3 Span ID',
    description: 'Generate Zipkin B3 span ID header',
    args: [],
    run() {
      return randomHex(8);
    }
  },

  {
    name: 'zipkin_parent_span_id',
    displayName: 'Trace Headers:Zipkin B3 Parent Span ID',
    description: 'Generate Zipkin B3 parent span ID header',
    args: [],
    run() {
      return randomHex(8);
    }
  },

  {
    name: 'zipkin_sampled',
    displayName: 'Trace Headers:Zipkin B3 Sampled',
    description: 'Generate Zipkin B3 sampled header',
    args: [
      {
        displayName: 'Trace Headers:Sampled',
        type: 'boolean',
        defaultValue: true
      }
    ],
    run(context, sampled) {
      return sampled ? '1' : '0';
    }
  },

  {
    name: 'zipkin_flags',
    displayName: 'Trace Headers:Zipkin B3 Flags',
    description: 'Generate Zipkin B3 flags header',
    args: [],
    run() {
      return '0';
    }
  },

  {
    name: 'zipkin_b3_single',
    displayName: 'Trace Headers:Zipkin B3 Single Header',
    description: 'Generate Zipkin B3 single header format',
    args: [
      {
        displayName: 'Trace Headers:Sampled',
        type: 'boolean',
        defaultValue: true
      }
    ],
    run(context, sampled) {
      const traceId = randomHex(16);
      const spanId = randomHex(8);
      const sampledFlag = sampled ? '1' : '0';
      return `${traceId}-${spanId}-${sampledFlag}`;
    }
  },

  // New Relic Headers
  {
    name: 'newrelic_header',
    displayName: 'Trace Headers:New Relic Header',
    description: 'Generate New Relic distributed tracing header',
    args: [
      {
        displayName: 'Trace Headers:Account ID',
        type: 'string',
        defaultValue: '1234567'
      },
      {
        displayName: 'Trace Headers:App ID',
        type: 'string',
        defaultValue: '7654321'
      }
    ],
    run(context, accountId, appId) {
      const payload = {
        v: [0, 1],
        d: {
          ty: 'App',
          ac: accountId,
          ap: appId,
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
    displayName: 'Trace Headers:New Relic ID',
    description: 'Generate New Relic ID header',
    args: [],
    run() {
      return randomHex(8);
    }
  },

  {
    name: 'newrelic_transaction',
    displayName: 'Trace Headers:New Relic Transaction',
    description: 'Generate New Relic transaction header',
    args: [],
    run() {
      return randomHex(16);
    }
  },

  // Google Cloud Trace
  {
    name: 'gcloud_trace_context',
    displayName: 'Trace Headers:Google Cloud Trace Context',
    description: 'Generate Google Cloud trace context header',
    args: [],
    run() {
      return `${randomHex(16)}/${randomNumber()};o=1`;
    }
  },

  {
    name: 'goog_trace',
    displayName: 'Trace Headers:Google Trace',
    description: 'Generate Google trace header',
    args: [],
    run() {
      return `${randomHex(16)}/${randomNumber()}`;
    }
  },

  // CloudFlare Headers
  {
    name: 'cloudflare_ray',
    displayName: 'Trace Headers:CloudFlare Ray ID',
    description: 'Generate CloudFlare Ray ID header',
    args: [],
    run() {
      const dcs = ['DFW', 'LAX', 'ORD', 'JFK', 'LHR', 'NRT', 'SJC', 'SEA', 'MIA', 'ATL', 'BOS', 'IAD'];
      const dc = dcs[Math.floor(Math.random() * dcs.length)];
      return `${randomHex(8)}-${dc}`;
    }
  },

  {
    name: 'cloudflare_request_id',
    displayName: 'Trace Headers:CloudFlare Request ID',
    description: 'Generate CloudFlare request ID header',
    args: [],
    run() {
      return randomHex(16);
    }
  },

  // Sentry Headers
  {
    name: 'sentry_trace',
    displayName: 'Trace Headers:Sentry Trace',
    description: 'Generate Sentry trace header',
    args: [
      {
        displayName: 'Trace Headers:Sampled',
        type: 'boolean',
        defaultValue: true
      }
    ],
    run(context, sampled) {
      const traceId = randomHex(16);
      const spanId = randomHex(8);
      const sampledFlag = sampled ? '1' : '0';
      return `${traceId}-${spanId}-${sampledFlag}`;
    }
  },

  {
    name: 'sentry_baggage',
    displayName: 'Trace Headers:Sentry Baggage',
    description: 'Generate Sentry baggage header',
    args: [
      {
        displayName: 'Trace Headers:Environment',
        type: 'string',
        defaultValue: 'production'
      }
    ],
    run(context, environment) {
      return `sentry-environment=${environment},sentry-trace_id=${randomHex(16)}`;
    }
  },

  // Elastic APM
  {
    name: 'elastic_traceparent',
    displayName: 'Trace Headers:Elastic APM Traceparent',
    description: 'Generate Elastic APM traceparent header (W3C format)',
    args: [
      {
        displayName: 'Trace Headers:Sampled',
        type: 'boolean',
        defaultValue: true
      }
    ],
    run(context, sampled) {
      const traceId = randomHex(16);
      const spanId = randomHex(8);
      const flags = sampled ? '01' : '00';
      return `00-${traceId}-${spanId}-${flags}`;
    }
  },

  {
    name: 'elastic_tracestate',
    displayName: 'Trace Headers:Elastic APM Tracestate',
    description: 'Generate Elastic APM tracestate header',
    args: [],
    run() {
      return `es=s:1.0`;
    }
  },

  // Dynatrace Headers
  {
    name: 'dynatrace_header',
    displayName: 'Trace Headers:Dynatrace Header',
    description: 'Generate Dynatrace tracing header',
    args: [
      {
        displayName: 'Trace Headers:Application ID',
        type: 'string',
        defaultValue: 'APPLICATION-12345'
      }
    ],
    run(context, appId) {
      const traceId = randomNumber();
      const spanId = randomNumber();
      return `FW4;${traceId};${spanId};1;${appId}`;
    }
  },

  {
    name: 'dynatrace_origin',
    displayName: 'Trace Headers:Dynatrace Origin',
    description: 'Generate Dynatrace origin header',
    args: [],
    run() {
      return `dt=${randomHex(8)}`;
    }
  },

  // AppDynamics
  {
    name: 'appdynamics_header',
    displayName: 'Trace Headers:AppDynamics Header',
    description: 'Generate AppDynamics singularityheader',
    args: [],
    run() {
      return `${randomHex(8)}-${randomHex(4)}-${randomHex(4)}-${randomHex(4)}-${randomHex(12)}`;
    }
  },

  // Honeycomb
  {
    name: 'honeycomb_trace',
    displayName: 'Trace Headers:Honeycomb Trace',
    description: 'Generate Honeycomb trace header',
    args: [
      {
        displayName: 'Trace Headers:Dataset',
        type: 'string',
        defaultValue: 'my-service'
      }
    ],
    run(context, dataset) {
      return randomHex(16);
    }
  },

  {
    name: 'honeycomb_dataset',
    displayName: 'Trace Headers:Honeycomb Dataset',
    description: 'Generate Honeycomb dataset header',
    args: [
      {
        displayName: 'Trace Headers:Dataset Name',
        type: 'string',
        defaultValue: 'my-service'
      }
    ],
    run(context, dataset) {
      return dataset;
    }
  },

  {
    name: 'honeycomb_samplerate',
    displayName: 'Trace Headers:Honeycomb Sample Rate',
    description: 'Generate Honeycomb sample rate header',
    args: [
      {
        displayName: 'Trace Headers:Sample Rate',
        type: 'enum',
        defaultValue: '1',
        options: [
          { displayName: 'Trace Headers:1 (100%)', value: '1' },
          { displayName: 'Trace Headers:10 (10%)', value: '10' },
          { displayName: 'Trace Headers:100 (1%)', value: '100' }
        ]
      }
    ],
    run(context, rate) {
      return rate;
    }
  },

  // LightStep
  {
    name: 'lightstep_span_context',
    displayName: 'Trace Headers:LightStep Span Context',
    description: 'Generate LightStep span context header',
    args: [],
    run() {
      return randomHex(16);
    }
  },

  // Istio/Envoy
  {
    name: 'envoy_request_id',
    displayName: 'Trace Headers:Envoy Request ID',
    description: 'Generate Envoy request ID header',
    args: [],
    run() {
      return randomUUID();
    }
  },

  {
    name: 'envoy_original_path',
    displayName: 'Trace Headers:Envoy Original Path',
    description: 'Generate Envoy original path header',
    args: [
      {
        displayName: 'Trace Headers:Original Path',
        type: 'string',
        defaultValue: '/api/v1/users'
      }
    ],
    run(context, path) {
      return path;
    }
  },

  // Tyk API Gateway Headers
  {
    name: 'tyk_trace_id',
    displayName: 'Trace Headers:Tyk Trace ID',
    description: 'Generate Tyk API Gateway trace ID header',
    args: [
      {
        displayName: 'Trace Headers:Format',
        type: 'enum',
        defaultValue: 'hex',
        options: [
          { displayName: 'Trace Headers:Hexadecimal', value: 'hex' },
          { displayName: 'Trace Headers:UUID', value: 'uuid' },
          { displayName: 'Trace Headers:Numeric', value: 'numeric' }
        ]
      }
    ],
    run(context, format) {
      if (format === 'uuid') return randomUUID();
      if (format === 'numeric') return randomNumber();
      return randomHex(16);
    }
  },

  {
    name: 'tyk_request_id',
    displayName: 'Trace Headers:Tyk Request ID',
    description: 'Generate Tyk API Gateway request ID header',
    args: [],
    run() {
      return randomUUID();
    }
  },

  {
    name: 'tyk_authorization',
    displayName: 'Trace Headers:Tyk Authorization',
    description: 'Generate Tyk authorization header (for management API)',
    args: [
      {
        displayName: 'Trace Headers:Secret Key',
        type: 'string',
        defaultValue: 'your-tyk-secret-key'
      }
    ],
    run(context, secretKey) {
      return secretKey;
    }
  },

  {
    name: 'tyk_version',
    displayName: 'Trace Headers:Tyk API Version',
    description: 'Generate Tyk API version header',
    args: [
      {
        displayName: 'Trace Headers:Version',
        type: 'string',
        defaultValue: 'v1'
      }
    ],
    run(context, version) {
      return version;
    }
  },

  {
    name: 'tyk_base_api_id',
    displayName: 'Trace Headers:Tyk Base API ID',
    description: 'Generate Tyk base API ID header for versioned APIs',
    args: [],
    run() {
      return randomHex(24);
    }
  },

  {
    name: 'tyk_session_id',
    displayName: 'Trace Headers:Tyk Session ID',
    description: 'Generate Tyk session identifier',
    args: [],
    run() {
      return 'tyk-' + randomUUID();
    }
  },

  // Snowflake ID Headers
  {
    name: 'snowflake_id',
    displayName: 'Trace Headers:Snowflake ID',
    description: 'Generate a Twitter-style Snowflake ID (64-bit distributed unique identifier)',
    args: [
      {
        displayName: 'Trace Headers:Machine ID',
        type: 'number',
        defaultValue: 0
      },
      {
        displayName: 'Trace Headers:Epoch Type',
        type: 'enum',
        defaultValue: 'twitter',
        options: [
          { displayName: 'Trace Headers:Twitter (Nov 4, 2010)', value: 'twitter' },
          { displayName: 'Trace Headers:Discord (Jan 1, 2015)', value: 'discord' },
          { displayName: 'Trace Headers:Unix Epoch (Jan 1, 1970)', value: 'unix' },
          { displayName: 'Trace Headers:Custom', value: 'custom' }
        ]
      },
      {
        displayName: 'Trace Headers:Custom Epoch (ms)',
        type: 'number',
        defaultValue: 1288834974657
      }
    ],
    run(context, machineId, epochType, customEpoch) {
      let epoch;
      switch (epochType) {
        case 'twitter': epoch = 1288834974657; break;
        case 'discord': epoch = 1420070400000; break;
        case 'unix': epoch = 0; break;
        case 'custom': epoch = customEpoch; break;
        default: epoch = 1288834974657;
      }
      return generateSnowflake(epoch, machineId);
    }
  },

  {
    name: 'twitter_snowflake',
    displayName: 'Trace Headers:Twitter Snowflake',
    description: 'Generate a Twitter Snowflake ID using Twitter\'s epoch',
    args: [
      {
        displayName: 'Trace Headers:Machine ID',
        type: 'number',
        defaultValue: 0
      }
    ],
    run(context, machineId) {
      return generateSnowflake(1288834974657, machineId);
    }
  },

  {
    name: 'discord_snowflake',
    displayName: 'Trace Headers:Discord Snowflake',
    description: 'Generate a Discord Snowflake ID using Discord\'s epoch',
    args: [
      {
        displayName: 'Trace Headers:Machine ID',
        type: 'number',
        defaultValue: 0
      }
    ],
    run(context, machineId) {
      return generateSnowflake(1420070400000, machineId);
    }
  },

  {
    name: 'custom_snowflake',
    displayName: 'Trace Headers:Custom Snowflake ID',
    description: 'Generate a custom Snowflake ID with configurable parameters',
    args: [
      {
        displayName: 'Trace Headers:Epoch Start (ms)',
        type: 'number',
        defaultValue: 1609459200000
      },
      {
        displayName: 'Trace Headers:Machine ID',
        type: 'number',
        defaultValue: 0
      }
    ],
    run(context, epochStart, machineId) {
      return generateSnowflake(epochStart, machineId);
    }
  },

  // Generic Correlation Headers
  {
    name: 'correlation_id',
    displayName: 'Trace Headers:Correlation ID',
    description: 'Generate a correlation ID header',
    args: [
      {
        displayName: 'Trace Headers:Format',
        type: 'enum',
        defaultValue: 'uuid',
        options: [
          { displayName: 'Trace Headers:UUID', value: 'uuid' },
          { displayName: 'Trace Headers:Hex (64-bit)', value: 'hex64' },
          { displayName: 'Trace Headers:Hex (128-bit)', value: 'hex128' },
          { displayName: 'Trace Headers:Numeric', value: 'numeric' }
        ]
      }
    ],
    run(context, format) {
      switch (format) {
        case 'uuid': return randomUUID();
        case 'hex64': return randomHex(8);
        case 'hex128': return randomHex(16);
        case 'numeric': return randomNumber();
        default: return randomUUID();
      }
    }
  },

  {
    name: 'trace_id',
    displayName: 'Trace Headers:Generic Trace ID',
    description: 'Generate a generic trace ID header',
    args: [],
    run() {
      return randomHex(16);
    }
  },

  {
    name: 'span_id',
    displayName: 'Trace Headers:Generic Span ID',
    description: 'Generate a generic span ID header',
    args: [],
    run() {
      return randomHex(8);
    }
  },

  {
    name: 'parent_id',
    displayName: 'Trace Headers:Generic Parent ID',
    description: 'Generate a generic parent ID header',
    args: [],
    run() {
      return randomHex(8);
    }
  },

  {
    name: 'operation_id',
    displayName: 'Trace Headers:Operation ID',
    description: 'Generate an operation ID header',
    args: [],
    run() {
      return randomUUID();
    }
  },

  {
    name: 'session_id',
    displayName: 'Trace Headers:Session ID',
    description: 'Generate a session ID header',
    args: [],
    run() {
      return 'sess_' + randomHex(16);
    }
  },

  {
    name: 'user_id',
    displayName: 'Trace Headers:User ID',
    description: 'Generate a user ID header',
    args: [
      {
        displayName: 'Trace Headers:Format',
        type: 'enum',
        defaultValue: 'numeric',
        options: [
          { displayName: 'Trace Headers:Numeric', value: 'numeric' },
          { displayName: 'Trace Headers:UUID', value: 'uuid' },
          { displayName: 'Trace Headers:Hex', value: 'hex' }
        ]
      }
    ],
    run(context, format) {
      switch (format) {
        case 'numeric': return Math.floor(Math.random() * 1000000).toString();
        case 'uuid': return randomUUID();
        case 'hex': return randomHex(8);
        default: return Math.floor(Math.random() * 1000000).toString();
      }
    }
  },

  {
    name: 'tenant_id',
    displayName: 'Trace Headers:Tenant ID',
    description: 'Generate a tenant ID header',
    args: [],
    run() {
      return 'tenant_' + randomHex(8);
    }
  },

  {
    name: 'application_id',
    displayName: 'Trace Headers:Application ID',
    description: 'Generate an application ID header',
    args: [],
    run() {
      return 'app_' + randomHex(12);
    }
  },

  {
    name: 'service_id',
    displayName: 'Trace Headers:Service ID',
    description: 'Generate a service ID header',
    args: [],
    run() {
      return 'svc_' + randomHex(10);
    }
  },

  // Custom Trace Header Builder
  {
    name: 'custom_trace_header',
    displayName: 'Trace Headers:Custom Trace Header',
    description: 'Generate a custom trace header with configurable format',
    args: [
      {
        displayName: 'Trace Headers:Format',
        type: 'string',
        defaultValue: '{traceId}-{spanId}'
      },
      {
        displayName: 'Trace Headers:Trace ID Length',
        type: 'enum',
        defaultValue: '128',
        options: [
          { displayName: 'Trace Headers:64-bit', value: '64' },
          { displayName: 'Trace Headers:128-bit', value: '128' }
        ]
      }
    ],
    run(context, format, traceIdLength) {
      const traceId = traceIdLength === '128' ? randomHex(16) : randomHex(8);
      const spanId = randomHex(8);
      const ts = timestamp();
      
      return format
        .replace(/{traceId}/g, traceId)
        .replace(/{spanId}/g, spanId)
        .replace(/{timestamp}/g, ts);
    }
  }
];