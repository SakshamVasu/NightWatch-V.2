/**
 * Public parser entry point.
 *
 * The whole app imports from here:  import { parseNmap } from './parser'
 */
export * from './types';
export { analyze } from './analyze';
export { parseAny as parseNmap, detectFormat } from './formats';
export { buildExploitation } from './exploitation';
export { buildRemediation } from './remediation';
export { buildReportHtml, openReport, type ReportMeta } from './report';
export { answerLocally, buildScanContext, type ChatMsg } from './localAssistant';
export { askAi, PROVIDERS, type Provider, type AiConfig } from './aiChat';
export { stripAnsi, normalizeLines } from './util';
