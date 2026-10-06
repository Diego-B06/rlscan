#!/usr/bin/env node
import { run } from '../src/index.js';

run(process.argv).catch((err) => {
  console.error('rlscan falló inesperadamente:', err);
  process.exitCode = 2;
});
