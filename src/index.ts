#!/usr/bin/env node
import { buildProgram } from "./cli.js";

const program = buildProgram();
program.parseAsync(process.argv).catch((err) => {
  console.error(`Fatal error: ${(err as Error).message}`);
  process.exitCode = 3;
});
