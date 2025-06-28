# Insomnia Trace Headers Plugin

A comprehensive Insomnia plugin for generating distributed tracing headers and Snowflake IDs for various APM and observability systems using cryptographically secure random number generation.

## Features

✅ **Cryptographically Secure**: Uses Node.js `crypto` module for generating random IDs  
✅ **Industry Standards**: Supports all major tracing and APM systems  
✅ **Snowflake IDs**: Twitter-style 64-bit distributed unique identifiers  
✅ **Configurable Options**: Customizable sampling, formats, and system-specific parameters  
✅ **Easy Integration**: Simple template tag interface  

## Installation

### Method 1: Local Development
1. Create a folder named `insomnia-plugin-trace-headers` in your Insomnia plugins directory:
   - **macOS**: `~/Library/Application Support/Insomnia/plugins/`
   - **Windows**: `%APPDATA%\Insomnia\plugins\`
   - **Linux**: `~/.config/Insomnia/plugins/`

2. Copy `package.json` and `app.js` into this folder
3. Restart Insomnia or the plugin will be automatically detected

### Method 2: Via Insomnia UI
1. Open Insomnia Preferences (cog icon)
2. Go to Plugins tab
3. Click "Generate New Plugin"
4. Enter "trace-headers" as plugin name
5. Replace the generated files with the provided `package.json` and `app.js`

## Usage

Once installed, you can use the template tags anywhere in Insomnia where template tags are supported (headers, body, query parameters, etc.).

To insert a template tag:
1. Press `Ctrl+Space` (or `Cmd+Space` on macOS) in any text field
2. Search for the desired trace header template tag
3. Configure the options if any are available

## Supported Systems

### OpenTelemetry / W3C Trace Context
- **W3C Traceparent**: Generates standard W3C traceparent headers
  - Format: `00-{128-bit-trace-id}-{64-bit-span-id}-{flags}`
  - Options: Version, Sampled flag

### Datadog APM
- **Datadog Trace ID**: Numeric trace identifier
- **Datadog Parent ID**: Numeric span/parent identifier  
- **Datadog Sampling Priority**: Sampling decision (-1 to 2)
- **Datadog Origin**: Origin of the trace (e.g., "synthetics")

### AWS X-Ray
- **AWS X-Ray Trace ID**: Root trace identifier
  - Format: `Root=1-{timestamp}-{96-bit-random}`
- **AWS Request ID**: UUID format request identifier

### Azure Application Insights
- **Azure Request ID**: UUID format request identifier
- **Azure Request Context**: Application context header
  - Format: `appId=cid-v1:{app-id}`

### Jaeger
- **Jaeger Trace ID**: Uber trace context format
  - Format: `{128-bit-trace-id}:{64-bit-span-id}:{64-bit-parent-id}:{flags}`

### Zipkin B3
- **Zipkin B3 Trace ID**: Configurable 64-bit or 128-bit trace ID
- **Zipkin B3 Span ID**: 64-bit span identifier
- **Zipkin B3 Single Header**: Combined B3 header
  - Format: `{trace-id}-{span-id}-{sampled}`

### New Relic
- **New Relic Header**: Base64 encoded distributed tracing payload
- Options: Account ID, Application ID

### Google Cloud Trace
- **Google Cloud Trace Context**: GCP trace format
  - Format: `{128-bit-trace-id}/{span-id};o=1`

### CloudFlare
- **CloudFlare Ray ID**: Ray ID with datacenter suffix
  - Format: `{64-bit-hex}-{datacenter}`

### Sentry
- **Sentry Trace**: Sentry performance monitoring header
  - Format: `{32-char-trace-id}-{16-char-span-id}-{sampled}`

### Elastic APM
- **Elastic APM Traceparent**: W3C format for Elastic
  - Format: `00-{128-bit-trace-id}-{64-bit-span-id}-{flags}`

### Dynatrace
- **Dynatrace Header**: Dynatrace tracing format
  - Format: `FW4;{trace-id};{span-id};1;{app-id}`

### Tyk API Gateway
- **Tyk Trace ID**: Custom trace identifier for Tyk Gateway
  - Options: Hexadecimal (128-bit), UUID, or Numeric format
- **Tyk Request ID**: UUID format request identifier for Tyk
- **Tyk Authorization**: Management API authorization header
- **Tyk API Version**: API version header for versioned APIs
- **Tyk Base API ID**: Base API identifier for versioned APIs
- **Tyk Session ID**: Session identifier with "tyk-" prefix

### Snowflake IDs
- **Snowflake ID**: Twitter-style 64-bit distributed unique identifier
  - Options: Twitter, Discord, Unix, or custom epoch
  - Configurable machine/worker ID (0-1023)
- **Twitter Snowflake**: Official Twitter Snowflake format
  - Epoch: November 4, 2010, 01:42:54 UTC
- **Discord Snowflake**: Discord-compatible Snowflake format
  - Epoch: January 1, 2015, 00:00:00 UTC
- **Custom Snowflake**: Fully configurable Snowflake ID
  - Custom epoch and machine ID settings

### Generic/Custom Headers
- **Correlation ID**: Configurable correlation identifier
  - Options: UUID, 64-bit hex, 128-bit hex, or numeric format
- **Custom Trace Header**: Fully customizable format using placeholders
  - Placeholders: `{traceId}`, `{spanId}`, `{timestamp}`

## Example Usage

### Setting up W3C Traceparent Header
1. In your request headers, add a new header named `traceparent`
2. Press `Ctrl+Space` in the value field
3. Select "W3C Traceparent" from the template tags
4. Configure version (default: "00") and sampling (default: true)

### Setting up Multiple Datadog Headers
```
x-datadog-trace-id: {% datadog-trace-id %}
x-datadog-parent-id: {% datadog-parent-id %}
x-datadog-sampling-priority: {% datadog-sampling-priority %}
x-datadog-origin: {% datadog-origin %}
```

### Setting up Tyk API Gateway Headers
```
x-tyk-traceid: {% tyk-trace-id %}
x-tyk-request-id: {% tyk-request-id %}
x-tyk-authorization: {% tyk-authorization %}
x-tyk-version: {% tyk-version %}
```

### Using Snowflake IDs
```
x-snowflake-id: {% snowflake-id %}
x-twitter-snowflake: {% twitter-snowflake %}
x-discord-snowflake: {% discord-snowflake %}
x-custom-snowflake: {% custom-snowflake %}
```

### Custom Format Example
Use the "Custom Trace Header" template tag with format: `trace-{traceId}-span-{spanId}-ts-{timestamp}`

## Complete Header Reference

| System | Header Name | Template Tag |
|--------|-------------|--------------|
| W3C/OpenTelemetry | `traceparent` | `traceparent` |
| Datadog | `x-datadog-trace-id` | `datadog-trace-id` |
| Datadog | `x-datadog-parent-id` | `datadog-parent-id` |
| Datadog | `x-datadog-sampling-priority` | `datadog-sampling-priority` |
| Datadog | `x-datadog-origin` | `datadog-origin` |
| AWS X-Ray | `x-amzn-trace-id` | `aws-trace-id` |
| AWS | `x-amzn-requestid` | `aws-request-id` |
| Azure | `request-id` | `azure-request-id` |
| Azure | `request-context` | `azure-request-context` |
| Jaeger | `uber-trace-id` | `jaeger-trace-id` |
| Zipkin | `x-b3-traceid` | `zipkin-trace-id` |
| Zipkin | `x-b3-spanid` | `zipkin-span-id` |
| Zipkin | `b3` | `zipkin-b3-single` |
| New Relic | `newrelic` | `newrelic-header` |
| Google Cloud | `x-cloud-trace-context` | `gcloud-trace-context` |
| CloudFlare | `cf-ray` | `cloudflare-ray` |
| Sentry | `sentry-trace` | `sentry-trace` |
| Elastic APM | `elastic-apm-traceparent` | `elastic-traceparent` |
| Dynatrace | `x-dynatrace` | `dynatrace-header` |
| Tyk Gateway | `x-tyk-traceid` | `tyk-trace-id` |
| Tyk Gateway | `x-tyk-request-id` | `tyk-request-id` |
| Tyk Gateway | `x-tyk-authorization` | `tyk-authorization` |
| Tyk Gateway | `x-tyk-version` | `tyk-version` |
| Tyk Gateway | `x-tyk-base-api-id` | `tyk-base-api-id` |
| Tyk Gateway | `x-tyk-session-id` | `tyk-session-id` |
| Snowflake | `x-snowflake-id` | `snowflake-id` |
| Twitter | `x-twitter-snowflake` | `twitter-snowflake` |
| Discord | `x-discord-snowflake` | `discord-snowflake` |
| Custom | `x-custom-snowflake` | `custom-snowflake` |
| Generic | `x-correlation-id` | `correlation-id` |
| Custom | (any name) | `custom-trace-header` |

## Security & Quality

This plugin uses Node.js built-in `crypto.randomBytes()` for generating all random values, ensuring:

- **Cryptographically secure random number generation**
- **High entropy** for trace and span IDs
- **No predictable patterns** in generated identifiers
- **Compliance** with security best practices for distributed tracing

All generated IDs have sufficient randomness to avoid collisions in distributed systems.

## Snowflake ID Format

Snowflake IDs are 64-bit integers used in distributed computing, originally created by Twitter. The format consists of:
- **1 bit**: Sign bit (always 0)
- **41 bits**: Timestamp (milliseconds since chosen epoch)
- **10 bits**: Machine/Worker ID (0-1023)
- **12 bits**: Sequence number (0-4095)

**Key Benefits:**
- **Time-sortable**: IDs are chronologically ordered
- **Distributed**: Multiple machines can generate IDs without coordination
- **High throughput**: Up to 4096 IDs per millisecond per machine
- **Collision-free**: Guaranteed uniqueness across distributed systems

**Common Epochs:**
- **Twitter**: November 4, 2010, 01:42:54 UTC (1288834974657)
- **Discord**: January 1, 2015, 00:00:00 UTC (1420070400000)
- **Custom**: Any timestamp you choose for your system

## Development

To extend this plugin:
1. Add new template tags to the `module.exports.templateTags` array in `app.js`
2. Each template tag needs: `name`, `displayName`, `description`, `args`, and `run` function
3. Use the helper functions for generating consistent ID formats

## All Available Template Tags

Here's a complete list of all available template tags in this plugin:

### Distributed Tracing
- `traceparent` - W3C Trace Context
- `datadog-trace-id` - Datadog Trace ID
- `datadog-parent-id` - Datadog Parent ID
- `datadog-sampling-priority` - Datadog Sampling Priority
- `datadog-origin` - Datadog Origin
- `aws-trace-id` - AWS X-Ray Trace ID
- `aws-request-id` - AWS Request ID
- `azure-request-id` - Azure Request ID
- `azure-request-context` - Azure Request Context
- `jaeger-trace-id` - Jaeger/Uber Trace ID
- `zipkin-trace-id` - Zipkin B3 Trace ID
- `zipkin-span-id` - Zipkin B3 Span ID
- `zipkin-b3-single` - Zipkin B3 Single Header
- `newrelic-header` - New Relic Distributed Tracing
- `gcloud-trace-context` - Google Cloud Trace Context
- `cloudflare-ray` - CloudFlare Ray ID
- `sentry-trace` - Sentry Trace Header
- `elastic-traceparent` - Elastic APM Traceparent
- `dynatrace-header` - Dynatrace Header

### Tyk API Gateway
- `tyk-trace-id` - Tyk Trace ID
- `tyk-request-id` - Tyk Request ID
- `tyk-authorization` - Tyk Authorization
- `tyk-version` - Tyk API Version
- `tyk-base-api-id` - Tyk Base API ID
- `tyk-session-id` - Tyk Session ID

### Snowflake IDs
- `snowflake-id` - General Snowflake ID
- `twitter-snowflake` - Twitter Snowflake
- `discord-snowflake` - Discord Snowflake
- `custom-snowflake` - Custom Snowflake

### Generic/Custom
- `correlation-id` - Correlation ID
- `custom-trace-header` - Custom Trace Header

## Contributing

Feel free to submit issues and enhancement requests!

## License

MIT License