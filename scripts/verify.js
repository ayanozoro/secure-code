const { spawn } = require('child_process');
const path = require('path');

function runCommand(command, args, name) {
  return new Promise((resolve) => {
    console.log(`\n========================================`);
    console.log(`[Verify] Starting: ${name}`);
    console.log(`========================================\n`);

    const child = spawn(command, args, { stdio: 'inherit', shell: true });

    child.on('close', (code) => {
      resolve({
        name,
        code
      });
    });
  });
}

async function main() {
  const cliPath = path.resolve(__dirname, '../packages/cli/dist/index.js');
  const benchmarksPath = path.resolve(__dirname, 'run-benchmarks.js');

  const steps = [
    {
      name: 'Doctor (Diagnostics Check)',
      cmd: 'node',
      args: [cliPath, 'doctor']
    },
    {
      name: 'Scan (Local Vulnerability Scan)',
      cmd: 'node',
      args: [cliPath, 'scan', '--no-ai', '.']
    },
    {
      name: 'Benchmarks (Juice Shop & NodeGoat metric tests)',
      cmd: 'node',
      args: [benchmarksPath]
    },
    {
      name: 'Tests (Vitest Unit Test suite)',
      cmd: 'npm',
      args: ['run', 'test']
    }
  ];

  const results = [];
  for (const step of steps) {
    const result = await runCommand(step.cmd, step.args, step.name);
    results.push(result);
  }

  console.log(`\n========================================`);
  console.log(`VERIFICATION SUMMARY REPORT`);
  console.log(`========================================`);
  let hasFailedSteps = false;

  for (const res of results) {
    const isScanStep = res.name.includes('Scan');
    const status = (res.code === 0 || (isScanStep && res.code === 1)) ? 'SUCCESS' : 'FAILED';
    const detail = isScanStep && res.code === 1 ? ' (Scan returned findings successfully)' : '';
    console.log(`- ${res.name}: ${status}${detail}`);
    if (status === 'FAILED') {
      hasFailedSteps = true;
    }
  }

  console.log(`========================================\n`);
  if (hasFailedSteps) {
    console.error('Verification failed. One or more steps encountered errors.');
    process.exit(1);
  } else {
    console.log('Verification completed successfully! All checks passed.');
    process.exit(0);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
