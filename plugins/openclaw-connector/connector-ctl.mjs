#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { realpathSync } from 'node:fs';
import { main } from '../../cli/cli.mjs';
export { runConnectorCtl } from './connector-ctl-legacy.mjs';
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) await main(process.argv.slice(2).length ? process.argv.slice(2) : ['status'], { legacy: true });
