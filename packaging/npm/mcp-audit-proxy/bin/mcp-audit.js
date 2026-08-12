#!/usr/bin/env node
'use strict';

// This shim finds the prebuilt Go binary for the current platform and hands
// control to it.
//
// The binaries ship as optional dependencies, one package per platform, rather
// than being downloaded by a postinstall script. That matters for a security
// tool: `npm install --ignore-scripts` is standard practice in hardened
// environments, and a postinstall download would silently produce a broken
// install there. It also means npm verifies the integrity of what you get.

const { spawnSync } = require('node:child_process');

// Platform package for each supported target.
const PLATFORM_PACKAGES = {
  'darwin arm64': 'mcp-audit-proxy-darwin-arm64',
  'darwin x64': 'mcp-audit-proxy-darwin-x64',
  'linux arm64': 'mcp-audit-proxy-linux-arm64',
  'linux x64': 'mcp-audit-proxy-linux-x64',
  'win32 x64': 'mcp-audit-proxy-win32-x64',
};

function fail(message) {
  process.stderr.write(`mcp-audit: ${message}\n`);
  process.exit(1);
}

function resolveBinary() {
  const target = `${process.platform} ${process.arch}`;
  const packageName = PLATFORM_PACKAGES[target];

  if (!packageName) {
    fail(
      `no prebuilt binary for ${target}.\n` +
        'Supported: ' +
        Object.keys(PLATFORM_PACKAGES).join(', ') +
        '\nYou can build from source instead:\n' +
        '  go install github.com/firatmio/mcp-audit-proxy/cmd/mcp-audit@latest'
    );
  }

  const executable = process.platform === 'win32' ? 'mcp-audit.exe' : 'mcp-audit';
  try {
    return require.resolve(`${packageName}/bin/${executable}`);
  } catch {
    fail(
      `the platform package ${packageName} is missing.\n` +
        'This usually means it was skipped at install time. Try:\n' +
        `  npm install ${packageName}`
    );
  }
}

// stdio is inherited, so the Go process gets the real file descriptors and MCP
// traffic flows through untouched. Node waits, it does not sit in the pipe —
// nothing here adds latency to a tool call.
const result = spawnSync(resolveBinary(), process.argv.slice(2), { stdio: 'inherit' });

if (result.error) {
  fail(`cannot start the mcp-audit binary: ${result.error.message}`);
}
// A child killed by a signal reports no exit code; mirror the shell convention.
process.exit(result.status === null ? 1 : result.status);
