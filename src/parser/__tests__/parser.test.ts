/**
 * Parser test suite — runs on Node's built-in test runner, no dependencies:
 *   npm test           (package.json wires this to `node --test`)
 *
 * It exercises normal terminal captures plus normal, grepable, and XML fixtures,
 * including multiple Nmap versions, multi-host output, and IPv6 XML.
 *
 * The assertions check behaviour, not memorized numbers where avoidable, and
 * specifically verify the CONFIRMED / POTENTIAL / INFORMATIONAL discipline.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseNmap, stripAnsi } from '../index.ts';

const here = dirname(fileURLToPath(import.meta.url));
const samples = join(here, '..', '..', '..', 'samples');
const load = (f: string) => readFileSync(join(samples, f), 'utf8');

const meta = parseNmap(load('metasploitable2.nmap.txt'));
const multi = parseNmap(load('small-multihost.nmap.txt'));
const gnmap = parseNmap(load('small.gnmap'));
const xml = parseNmap(load('small.xml'));

// ---- preprocessing --------------------------------------------------------
test('stripAnsi removes escape sequences', () => {
  assert.equal(stripAnsi('\u001b[1;31mred\u001b[0m'), 'red');
});

test('tee prompt lines and sudo password prompt are ignored', () => {
  // multi fixture has a Kali prompt box + [sudo] password line; neither should
  // leak into hosts or ports.
  assert.ok(!multi.hosts.some((h) => /kali|sudo/i.test(h.ip)));
  assert.ok(multi.ports.every((p) => Number.isFinite(p.port)));
});

// ---- scan metadata --------------------------------------------------------
test('scan metadata parsed', () => {
  assert.equal(meta.scan.nmapVersion, '7.99');
  assert.match(meta.scan.command || '', /nmap/);
  assert.match(meta.scan.duration || '', /second/);
  assert.equal(multi.scan.nmapVersion, '7.94');
});

test('grepable and XML output retain host, port, and script data', () => {
  assert.equal(gnmap.hosts[0]?.ip, '10.10.10.5');
  assert.ok(gnmap.ports.some((p) => p.port === 80 && p.product === 'nginx'));
  assert.equal(xml.hosts[0]?.hostnames[0], 'target.local');
  assert.ok(xml.ports.some((p) => p.port === 21 && p.product === 'vsftpd'));
  assert.ok(xml.nseScripts.some((s) => s.id === 'ftp-vsftpd-backdoor' && s.host === '10.10.10.5'));
});

test('IPv6-only XML hosts and escaped script output are retained', () => {
  const scan = parseNmap(`<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" args="nmap -6 -oX - 2001:db8::8">
<host><status state="up"/><address addr="2001:db8::8" addrtype="ipv6"/>
<ports><port protocol="tcp" portid="8443"><state state="open"/><service name="https"/>
<script id="http-title" output="title: Research &amp; Development"/></port></ports></host></nmaprun>`);
  assert.equal(scan.hosts[0]?.ip, '2001:db8::8');
  assert.equal(scan.nseScripts[0]?.output, 'title: Research & Development');
});

// ---- hosts ----------------------------------------------------------------
test('single host parsed with os, mac, latency', () => {
  assert.equal(meta.hosts.length, 1);
  const h = meta.hosts[0];
  assert.equal(h.ip, '192.168.1.8');
  assert.equal(h.status, 'up');
  assert.match(h.os || '', /Linux/);
  assert.equal(h.vendor, 'VMware');
  assert.match(h.latency || '', /0\.0/);
});

test('multiple hosts parsed independently', () => {
  assert.equal(multi.hosts.length, 2);
  const byIp = Object.fromEntries(multi.hosts.map((h) => [h.ip, h]));
  assert.ok(byIp['10.10.10.5']);
  assert.ok(byIp['10.10.10.99']);
  // second host carries its hostname
  assert.ok(byIp['10.10.10.99'].hostnames.includes('scanme.example.com'));
});

// ---- ports & services -----------------------------------------------------
test('open ports parsed with product/version split', () => {
  const p21 = meta.ports.find((p) => p.port === 21);
  assert.equal(p21?.service, 'ftp');
  assert.equal(p21?.product, 'vsftpd');
  assert.equal(p21?.version, '2.3.4');
  const p22 = meta.ports.find((p) => p.port === 22);
  assert.equal(p22?.product, 'OpenSSH');
  assert.match(p22?.version || '', /4\.7p1/);
});

test('closed and filtered states are handled per-host', () => {
  const closed = multi.ports.find((p) => p.port === 443);
  assert.equal(closed?.state, 'closed');
  // 10.10.10.5 reports filtered ports via "Not shown"; open ports still parse
  assert.ok(multi.ports.some((p) => p.port === 80 && p.state === 'open'));
});

test('ports attribute to the correct host', () => {
  const p8080 = multi.ports.find((p) => p.port === 8080);
  assert.equal(p8080?.host, '10.10.10.99');
  const p22 = multi.ports.find((p) => p.port === 22);
  assert.equal(p22?.host, '10.10.10.5');
});

test('services grouped by normalized label', () => {
  const names = meta.services.map((s) => s.name);
  assert.ok(names.includes('FTP'));
  assert.ok(names.includes('MySQL'));
  assert.ok(names.includes('PostgreSQL'));
});

// ---- NSE + confidence discipline -----------------------------------------
test('NSE scripts are captured and attributed to ports', () => {
  const backdoor = meta.nseScripts.find((s) => s.id === 'ftp-vsftpd-backdoor');
  assert.ok(backdoor, 'vsftpd backdoor script present');
  assert.equal(backdoor?.port, 21);
  assert.match(backdoor?.state || '', /VULNERABLE/);
});

test('CONFIRMED vulnerabilities come only from explicit VULNERABLE state', () => {
  const confirmed = meta.vulnerabilities.filter((v) => v.confidence === 'CONFIRMED');
  const titles = confirmed.map((v) => v.title.toLowerCase());
  assert.ok(titles.some((t) => t.includes('vsftpd')));
  assert.ok(titles.some((t) => t.includes('distcc')));
  // Every confirmed vuln must cite an NSE source.
  assert.ok(confirmed.every((v) => v.source.startsWith('NSE:')));
});

test('NOT VULNERABLE scripts never become confirmed vulns', () => {
  const bad = meta.vulnerabilities.find(
    (v) => v.confidence === 'CONFIRMED' && /not vulnerable/i.test(v.evidence)
  );
  assert.equal(bad, undefined);
});

test('Vulners CVEs are POTENTIAL, never CONFIRMED', () => {
  const vulnersCards = meta.vulnerabilities.filter((v) => v.source === 'NSE: vulners');
  assert.ok(vulnersCards.length > 0);
  assert.ok(vulnersCards.every((v) => v.confidence === 'POTENTIAL'));
});

test('LIKELY VULNERABLE is treated as POTENTIAL, not CONFIRMED', () => {
  const slow = meta.vulnerabilities.find((v) => /slowloris/i.test(v.title));
  assert.ok(slow);
  assert.equal(slow?.confidence, 'POTENTIAL');
});

test('severity is never invented: no-score confirmed vuln is UNRATED', () => {
  const vsftpd = meta.vulnerabilities.find((v) => /vsftpd/i.test(v.title));
  // vsftpd backdoor has no NSE CVSS/risk line and no scored CVE -> UNRATED.
  // The finding itself is NSE-sourced, so severitySource is 'nse' (the check
  // that produced it), but no fake severity number was assigned.
  assert.equal(vsftpd?.severity, 'UNRATED');
  assert.equal(vsftpd?.confidence, 'CONFIRMED');
});

// ---- web ------------------------------------------------------------------
test('web findings detect server, directories and methods', () => {
  const web80 = meta.webFindings.find((w) => w.port === 80);
  assert.ok(web80);
  assert.match(web80?.server || '', /Apache/);
  assert.ok(web80!.directories.some((d) => /phpMyAdmin/i.test(d)));
  assert.ok(web80!.methods.includes('GET'));
});

// ---- os & traceroute ------------------------------------------------------
test('OS/network and traceroute parsed', () => {
  const on = meta.osNetwork[0];
  assert.match(on.os || '', /Linux/);
  assert.equal(on.mac, '00:0C:29:F9:F4:00');
  assert.ok(on.traceroute.length >= 1);
  assert.equal(on.traceroute[0].address, '192.168.1.8');
});

// ---- stats ----------------------------------------------------------------
test('stats reflect parsed data', () => {
  assert.equal(meta.stats.hostsUp, 1);
  assert.equal(meta.stats.openPorts, 30);
  assert.ok(meta.stats.confirmed >= 5);
  assert.ok(meta.stats.potential >= 5);
  assert.ok(meta.stats.informational > 20);
  assert.ok(meta.stats.cves > 100);
});

// ---- robustness -----------------------------------------------------------
test('empty / junk input does not throw', () => {
  assert.doesNotThrow(() => parseNmap(''));
  assert.doesNotThrow(() => parseNmap('not an nmap file at all\nrandom text'));
  const empty = parseNmap('');
  assert.equal(empty.hosts.length, 0);
  assert.equal(empty.ports.length, 0);
});
