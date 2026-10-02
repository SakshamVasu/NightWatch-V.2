// Minimal loader: let extensionless relative imports resolve to .ts files,
// so bundler-style source can run under `node --experimental-strip-types`.
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve as pathResolve } from 'node:path';

export async function resolve(specifier, context, next) {
  if ((specifier.startsWith('./') || specifier.startsWith('../')) && !/\.[mc]?[jt]s$/.test(specifier)) {
    const parentPath = context.parentURL ? dirname(fileURLToPath(context.parentURL)) : process.cwd();
    for (const cand of [specifier + '.ts', specifier + '/index.ts']) {
      const abs = pathResolve(parentPath, cand);
      if (existsSync(abs)) return next(pathToFileURL(abs).href, context);
    }
  }
  return next(specifier, context);
}
