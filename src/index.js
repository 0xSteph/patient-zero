// Programmatic entry point for embedders. The CLI lives in bin/cli.js.

export { loadIocs } from './ioc-loader.js';
export { renderTerminal, renderJson } from './reporter.js';
export { renderMarkdown } from './markdown-reporter.js';
export { scan as scanLockfiles } from './scanners/lockfiles.js';
export { scan as scanMcp } from './scanners/mcp.js';
export { scan as scanLocalFiles } from './scanners/local-files.js';
export { scan as scanProcesses } from './scanners/processes.js';
export { scan as scanGithub } from './scanners/github.js';
