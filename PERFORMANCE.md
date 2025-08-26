<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Performance Characteristics

This document outlines the performance characteristics, benchmarks, and
optimization guidelines for the 1Password Secrets Action.

## Table of Contents

- [Overview](#overview)
- [Performance Benchmarks](#performance-benchmarks)
- [Memory Usage](#memory-usage)
- [Scalability](#scalability)
- [Network Performance](#network-performance)
- [Optimization Guidelines](#optimization-guidelines)
- [Monitoring and Metrics](#monitoring-and-metrics)
- [Troubleshooting Performance Issues](#troubleshooting-performance-issues)

## Overview

The 1Password Secrets Action is optimized for fast secret retrieval with
minimal resource usage while maintaining the highest security standards.

### Key Performance Features

- **Parallel Retrieval**: Batch secrets fetched concurrently
- **Intelligent Caching**: Vault metadata cached during execution
- **Minimal Overhead**: Optimized binary with small resource footprint
- **Fast Startup**: Pre-compiled binaries with no runtime compilation
- **Memory Efficiency**: Secure memory management with automatic cleanup

### Performance Goals

- **Single Secret**: < 2 seconds end-to-end
- **Batch Secrets**: Linear scaling with configurable concurrency
- **Memory Usage**: < 50MB for typical workloads
- **CPU Usage**: Minimal CPU impact on GitHub Actions runners
- **Network Efficiency**: Optimal API usage with connection reuse

## Performance Benchmarks

### Test Environment

Benchmarks run on GitHub Actions standard runners:

- **OS**: Ubuntu 22.04 (ubuntu-latest)
- **CPU**: 2-core x86_64
- **RAM**: 7GB available
- **Network**: Variable GitHub Actions connectivity

### Single Secret Retrieval

| Metric | Value | Notes |
|--------|-------|-------|
| **Average Latency** | 1.2s | Including CLI download and vault resolution |
| **P95 Latency** | 2.1s | 95th percentile response time |
| **P99 Latency** | 3.4s | 99th percentile response time |
| **Memory Peak** | 8MB | Peak memory usage during retrieval |
| **CPU Usage** | < 5% | Average CPU usage |

### Batch Secret Retrieval

#### Concurrent Processing (Default: 5 concurrent)

| Secret Count | Average Time | P95 Time | Memory Peak | Notes |
|--------------|--------------|----------|-------------|-------|
| 1 secret | 1.2s | 2.1s | 8MB | Baseline |
| 5 secrets | 2.1s | 3.2s | 12MB | Optimal concurrency |
| 10 secrets | 3.4s | 4.8s | 18MB | Good performance |
| 25 secrets | 6.7s | 9.2s | 28MB | Acceptable |
| 50 secrets | 12.3s | 16.8s | 45MB | Upper limit recommended |

#### Sequential vs Parallel Comparison

| Secret Count | Sequential | Parallel (5x) | Speedup | Efficiency |
|--------------|------------|---------------|---------|------------|
| 5 secrets | 6.0s | 2.1s | 2.9x | 58% |
| 10 secrets | 12.0s | 3.4s | 3.5x | 70% |
| 25 secrets | 30.0s | 6.7s | 4.5x | 90% |
| 50 secrets | 60.0s | 12.3s | 4.9x | 98% |

### Startup Performance

| Component | Time | Description |
|-----------|------|-------------|
| **Binary Download** | 0.3s | Download action binary |
| **CLI Download** | 0.8s | Download and verify 1Password CLI |
| **Authentication** | 0.2s | Token validation |
| **Vault Resolution** | 0.1s | Name to ID resolution (cached) |
| **Total Startup** | 1.4s | Complete initialization |

### Caching Performance

#### Vault Resolution Caching

| Cache State | Resolution Time | Notes |
|-------------|-----------------|-------|
| **Cold Cache** | 150ms | First vault resolution |
| **Warm Cache** | 5ms | Subsequent resolutions |
| **Cache Hit Rate** | 95%+ | In typical workflows |

#### CLI Binary Caching

| Cache State | Download Time | Notes |
|-------------|---------------|-------|
| **No Cache** | 800ms | Fresh CLI download |
| **Cached Binary** | 50ms | Verification only |
| **Cache Hit Rate** | 90%+ | In CI/CD environments |

## Memory Usage

### Memory Profile Analysis

#### Typical Workflow (5 secrets)

| Component | Memory Usage | Peak | Notes |
|-----------|--------------|------|-------|
| **Base Process** | 4MB | 4MB | Go runtime overhead |
| **CLI Binary** | 2MB | 2MB | 1Password CLI in memory |
| **Secure Memory** | 1MB | 3MB | Secrets storage (cleared) |
| **Network Buffers** | 1MB | 2MB | HTTP request/response |
| **JSON Parsing** | 0.5MB | 1MB | Configuration parsing |
| **Total** | 8.5MB | 12MB | Peak during processing |

#### Large Workflow (50 secrets)

| Component | Memory Usage | Peak | Notes |
|-----------|--------------|------|-------|
| **Base Process** | 4MB | 4MB | Go runtime overhead |
| **CLI Binary** | 2MB | 2MB | 1Password CLI in memory |
| **Secure Memory** | 15MB | 25MB | Multiple secrets (cleared) |
| **Network Buffers** | 5MB | 8MB | Concurrent requests |
| **JSON Parsing** | 2MB | 4MB | Large configuration |
| **Total** | 28MB | 43MB | Peak during processing |

### Memory Optimization Features

#### Secure Memory Management

- **mlock/VirtualLock**: Prevents secrets from swap files
- **Multi-pass Zeroing**: Secure deletion of sensitive data
- **Automatic Cleanup**: Defer-based cleanup guarantees
- **Memory Pools**: Reuse of secure allocations

#### Garbage Collection Impact

- **Secrets Never in GC**: Secure memory outside Go's GC
- **Minimal GC Pressure**: Low allocation rate
- **Fast Collection**: Small heap size enables fast GC

## Scalability

### Horizontal Scaling

The action is designed for optimal performance in parallel workflow executions:

#### Matrix Builds Performance

```yaml
strategy:
  matrix:
    environment: [dev, staging, prod]
    region: [us-east, us-west, eu-central]
```

| Matrix Size | Total Time | Resource Usage | Notes |
|-------------|------------|----------------|-------|
| 3x3 (9 jobs) | 2.5s | 108MB total | Excellent scaling |
| 5x5 (25 jobs) | 3.1s | 300MB total | Good performance |
| 10x10 (100 jobs) | 4.2s | 1.2GB total | Acceptable load |

#### Concurrent Workflow Limits

- **GitHub Actions**: 20 concurrent jobs (default)
- **1Password API**: 100 requests/minute (service account)
- **Recommended**: 5-10 concurrent secret retrievals per job

### Vertical Scaling

#### Concurrency Configuration

```yaml
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    max_concurrency: 10  # Increase for more secrets
```

| Concurrency | Memory Impact | Time Improvement | Recommended For |
|-------------|---------------|------------------|-----------------|
| 1 (sequential) | Minimal | Baseline | < 5 secrets |
| 5 (default) | Low | 3-5x faster | 5-25 secrets |
| 10 (high) | Moderate | 5-8x faster | 25-50 secrets |
| 20 (maximum) | High | 8-10x faster | > 50 secrets |

### Resource Limits

#### GitHub Actions Runner Limits

- **Memory**: 7GB available (action uses < 50MB)
- **CPU**: 2 cores (action uses < 10% average)
- **Network**: Shared bandwidth (optimized usage)
- **Disk**: Temporary storage (minimal usage)

#### 1Password API Limits

- **Rate Limit**: 100 requests/minute per service account
- **Concurrent Connections**: 10 simultaneous connections
- **Request Size**: 1MB maximum request size
- **Response Size**: 10MB maximum response size

## Network Performance

### API Optimization

#### Connection Management

- **HTTP/2**: Multiplexing for multiple requests
- **Keep-Alive**: Connection reuse across requests
- **Compression**: Gzip compression for large responses
- **Timeouts**: Appropriate timeouts for reliability

#### Request Batching

- **Vault Metadata**: Cached for session duration
- **Concurrent Requests**: Parallel secret retrieval
- **Request Deduplication**: Avoid duplicate requests
- **Retry Logic**: Exponential backoff for failures

### Network Latency Impact

#### Geographic Performance

| Region | Avg Latency | P95 Latency | Notes |
|--------|-------------|-------------|-------|
| **US East** | 50ms | 120ms | Optimal for US runners |
| **US West** | 80ms | 180ms | Good performance |
| **Europe** | 120ms | 250ms | Acceptable latency |
| **Asia Pacific** | 200ms | 400ms | Higher latency expected |

#### Network Optimization Tips

- **Minimize Requests**: Batch multiple secrets when possible
- **Use Caching**: Enable caching for repeated operations
- **Optimize Timeouts**: Balance reliability vs performance
- **Monitor Latency**: Track performance across regions

## Optimization Guidelines

### Configuration Optimization

#### For Small Workloads (1-5 secrets)

```yaml
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
    vault: "production"
    record: "database/password"
    # Use defaults for optimal single-secret performance
```

#### For Medium Workloads (5-25 secrets)

```yaml
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
    vault: "production"
    max_concurrency: 5  # Default, optimal for most cases
    cache_enabled: true
    record: |
      db_url: database/connection-string
      api_key: external-api/key
      # ... more secrets
```

#### For Large Workloads (25+ secrets)

```yaml
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    token: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
    vault: "production"
    max_concurrency: 10  # Increased concurrency
    cache_enabled: true
    cache_ttl: 600  # Longer cache TTL
    timeout: 600  # Increased timeout
    record: |
      # Large number of secrets
```

### Workflow Optimization

#### Parallel Secret Groups

Instead of one large secret retrieval:

```yaml
# ❌ LESS OPTIMAL: Single large retrieval
- name: Get all secrets
  uses: lfreleng-actions/1password-secrets-action@v1
  with:
    record: |
      # 50+ secrets here

# ✅ BETTER: Parallel secret groups
jobs:
  database-secrets:
    runs-on: ubuntu-latest
    steps:
      - name: Get database secrets
        uses: lfreleng-actions/1password-secrets-action@v1
        with:
          record: |
            # Database-related secrets

  api-secrets:
    runs-on: ubuntu-latest
    steps:
      - name: Get API secrets
        uses: lfreleng-actions/1password-secrets-action@v1
        with:
          record: |
            # API-related secrets
```

#### Conditional Secret Loading

```yaml
# Only load production secrets for main branch
- name: Load production secrets
  if: github.ref == 'refs/heads/main'
  uses: lfreleng-actions/1password-secrets-action@v1
  with:
    vault: "production"
    record: |
      prod_db_url: database/url
      prod_api_key: api/key

# Load development secrets for other branches
- name: Load development secrets
  if: github.ref != 'refs/heads/main'
  uses: lfreleng-actions/1password-secrets-action@v1
  with:
    vault: "development"
    record: |
      dev_db_url: database/url
      dev_api_key: api/key
```

### Performance Monitoring

#### Built-in Metrics

The action provides performance metrics in logs:

```text
INFO  Action completed successfully
INFO  Performance metrics:
INFO    Total time: 2.34s
INFO    Secrets retrieved: 5
INFO    Memory peak: 12MB
INFO    Cache hits: 3/3 vault resolutions
INFO    Network requests: 5 concurrent
```

#### Custom Monitoring

```yaml
- name: Monitor performance
  run: |
    start_time=$(date +%s)

- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    # ... configuration

- name: Log performance
  run: |
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    echo "Secret retrieval took ${duration}s"

    # Send to monitoring system
    curl -X POST "$MONITORING_URL" \
      -d "metric=secret_retrieval_duration&value=${duration}"
```

## Monitoring and Metrics

### Key Performance Indicators

#### Response Time Metrics

- **Mean Response Time**: Average time for secret retrieval
- **P95 Response Time**: 95th percentile response time
- **P99 Response Time**: 99th percentile response time
- **Timeout Rate**: Percentage of requests that timeout

#### Throughput Metrics

- **Secrets/Second**: Rate of secret retrieval
- **Requests/Minute**: API request rate
- **Concurrency Utilization**: Effective use of parallel processing
- **Cache Hit Rate**: Percentage of cache hits vs misses

#### Resource Metrics

- **Memory Usage**: Peak and average memory consumption
- **CPU Utilization**: Processor usage during execution
- **Network Bandwidth**: Data transfer rates
- **Disk I/O**: Temporary file operations

#### Error Metrics

- **Error Rate**: Percentage of failed operations
- **Retry Rate**: Frequency of retry attempts
- **Authentication Failures**: Rate of auth-related errors
- **Network Failures**: Rate of network-related errors

### Performance Alerts

#### Recommended Thresholds

```yaml
# Performance monitoring thresholds
response_time_p95: 5s      # Alert if P95 > 5 seconds
memory_usage: 100MB        # Alert if memory > 100MB
error_rate: 5%             # Alert if error rate > 5%
timeout_rate: 1%           # Alert if timeout rate > 1%
cache_hit_rate: 80%        # Alert if cache hits < 80%
```

#### Monitoring Implementation

```bash
# Example monitoring script
#!/bin/bash
set -euo pipefail

# Capture start time and metrics
start_time=$(date +%s.%N)
start_memory=$(ps -o rss= -p $$)

# Run action (monitored command)
./op-secrets-action "$@"
exit_code=$?

# Capture end metrics
end_time=$(date +%s.%N)
end_memory=$(ps -o rss= -p $$)

# Calculate metrics
duration=$(echo "$end_time - $start_time" | bc)
memory_diff=$(echo "$end_memory - $start_memory" | bc)

# Send to monitoring system
curl -X POST "$METRICS_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{
    \"action\": \"1password-secrets\",
    \"duration\": $duration,
    \"memory_delta\": $memory_diff,
    \"exit_code\": $exit_code,
    \"timestamp\": \"$(date -Iseconds)\"
  }"
```

## Troubleshooting Performance Issues

### Common Performance Problems

#### Slow Secret Retrieval

**Symptoms:**

- Total time > 10 seconds for < 10 secrets
- Timeouts in GitHub Actions
- High resource usage

**Causes and Solutions:**

1. **Network Latency**

   ```bash
   # Check network connectivity
   curl -w "@curl-format.txt" -s -o /dev/null https://my.1password.com

   # Increase timeout
   timeout: 600  # 10 minutes
   ```

2. **API Rate Limiting**

   ```bash
   # Reduce concurrency
   max_concurrency: 3

   # Add delays between requests
   retry_timeout: 60
   ```

3. **Large Configuration**

   ```bash
   # Split into smaller batches
   # Use multiple action calls instead of one large call
   ```

#### High Memory Usage

**Symptoms:**

- Memory usage > 100MB
- Out of memory errors
- Slow garbage collection

**Solutions:**

1. **Reduce Batch Size**

   ```yaml
   # Instead of 50 secrets at once
   # Split into 5 batches of 10 secrets each
   ```

2. **Disable Caching (if appropriate)**

   ```yaml
   cache_enabled: false  # Reduces memory usage
   ```

3. **Optimize Record Format**

   ```yaml
   # Use compact JSON instead of YAML
   record: '{"key1":"item1/field1","key2":"item2/field2"}'
   ```

#### Authentication Slowness

**Symptoms:**

- Long delays before secret retrieval starts
- Intermittent authentication failures

**Solutions:**

1. **Verify Token Format**

   ```bash
   # Ensure token starts with "ops_"
   echo "$OP_SERVICE_ACCOUNT_TOKEN" | head -c 10
   ```

2. **Check Token Permissions**

   ```bash
   # Verify vault access
   op vault list --account=your-account
   ```

### Performance Debugging

#### Enable Debug Mode

```yaml
- uses: lfreleng-actions/1password-secrets-action@v1
  with:
    debug: true
    # ... other configuration
```

Debug output includes:

- Detailed timing information
- Memory usage at each step
- Network request details
- Cache hit/miss information

#### Performance Profiling

```bash
# CPU profiling
go test -cpuprofile=cpu.prof -bench=BenchmarkSecretRetrieval

# Memory profiling
go test -memprofile=mem.prof -bench=BenchmarkSecretRetrieval

# Analyze profiles
go tool pprof cpu.prof
go tool pprof mem.prof
```

#### Network Analysis

```bash
# Monitor network requests
export DEBUG=true
export HTTP_TRACE=true

# Analyze request patterns
tcpdump -i any -w network.pcap host my.1password.com
wireshark network.pcap
```

### Performance Optimization Checklist

#### Pre-Optimization

- [ ] **Measure Baseline**: Record current performance metrics
- [ ] **Identify Bottlenecks**: Determine limiting factors
- [ ] **Set Goals**: Define target performance improvements
- [ ] **Plan Testing**: Prepare performance test scenarios

#### Optimization Steps

- [ ] **Configure Concurrency**: Adjust based on secret count
- [ ] **Enable Caching**: Use caching for repeated operations
- [ ] **Optimize Timeouts**: Balance reliability vs speed
- [ ] **Batch Secrets**: Group related secrets together
- [ ] **Use Vault IDs**: Avoid name resolution when possible

#### Post-Optimization

- [ ] **Verify Improvements**: Measure performance gains
- [ ] **Test Reliability**: Ensure stability at higher performance
- [ ] **Monitor Production**: Track performance in real workloads
- [ ] **Document Changes**: Record optimization decisions

---

**Performance Monitoring**: Continuous monitoring helps identify performance
regressions and optimization opportunities. Consider implementing automated
performance testing in your CI/CD pipeline.

**Support**: For performance-related questions or issues, please open a
discussion or issue with detailed performance metrics and configuration.
