const { exec } = require('child_process');
const fs = require('fs/promises');
const path = require('path');

function runScan(targetPath) {
  return new Promise((resolve) => {
    const cliPath = path.resolve(__dirname, '../packages/cli/dist/index.js');
    const cmd = `node "${cliPath}" scan --no-ai -f sarif "${targetPath}"`;
    const start = Date.now();

    exec(cmd, { maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      const duration = (Date.now() - start) / 1000;
      try {
        const sarif = JSON.parse(stdout);
        resolve({
          success: true,
          sarif,
          duration,
          stderr
        });
      } catch (err) {
        resolve({
          success: false,
          error: err.message,
          stdout,
          stderr,
          duration
        });
      }
    });
  });
}

async function main() {
  console.log('Running Guardrail Security benchmarks...');

  const juiceShopPath = path.resolve(__dirname, '../benchmarks/juice-shop');
  const nodeGoatPath = path.resolve(__dirname, '../benchmarks/nodegoat');

  console.log(`Scanning Juice Shop at: ${juiceShopPath}`);
  const juiceResult = await runScan(juiceShopPath);

  console.log(`Scanning NodeGoat at: ${nodeGoatPath}`);
  const nodeGoatResult = await runScan(nodeGoatPath);

  // Generate metrics
  let markdown = `# Guardrail Security Scanner Benchmark Results\n\n`;
  markdown += `*Generated on: ${new Date().toISOString()}*\n\n`;
  markdown += `This report outlines the baseline scan metrics for the \`guardrail\` scanner against two popular vulnerable target codebases.\n\n`;
  markdown += `## Benchmark Overview\n\n`;
  markdown += `| Target | Language / Type | Scan Duration | Total Findings | High/Critical | Medium (Warning) | Low (Note) |\n`;
  markdown += `| ------ | --------------- | ------------- | -------------- | ------------- | ---------------- | ---------- |\n`;

  const targets = [
    { name: 'OWASP Juice-Shop', result: juiceResult },
    { name: 'OWASP NodeGoat', result: nodeGoatResult }
  ];

  for (const target of targets) {
    const { name, result } = target;
    if (!result.success) {
      markdown += `| ${name} | Error: ${result.error} | ${result.duration.toFixed(2)}s | - | - | - | - |\n`;
      continue;
    }

    const results = result.sarif.runs[0].results || [];
    const total = results.length;
    const errors = results.filter(r => r.level === 'error').length;
    const warnings = results.filter(r => r.level === 'warning').length;
    const notes = results.filter(r => r.level === 'note').length;

    markdown += `| ${name} | JS/TS Vulnerable App | ${result.duration.toFixed(2)}s | ${total} | ${errors} | ${warnings} | ${notes} |\n`;
  }

  markdown += `\n## Details & Severity Analysis\n\n`;

  for (const target of targets) {
    const { name, result } = target;
    markdown += `### ${name}\n\n`;
    if (!result.success) {
      markdown += `Failed to analyze: \`${result.error}\`\n\n`;
      continue;
    }

    const results = result.sarif.runs[0].results || [];
    if (results.length === 0) {
      markdown += `No findings detected.\n\n`;
      continue;
    }

    // Group findings by rule ID
    const rules = {};
    for (const res of results) {
      const ruleId = res.ruleId;
      rules[ruleId] = (rules[ruleId] || 0) + 1;
    }

    markdown += `**Vulnerability Findings Count by Rule ID:**\n\n`;
    markdown += `| Rule ID | Count |\n`;
    markdown += `| ------- | ----- |\n`;
    for (const ruleId of Object.keys(rules).sort()) {
      markdown += `| ${ruleId} | ${rules[ruleId]} |\n`;
    }
    markdown += `\n`;
  }

  const resultsPath = path.resolve(__dirname, '../benchmarks/results.md');
  await fs.writeFile(resultsPath, markdown, 'utf8');
  console.log(`Benchmark completed successfully. Results written to ${resultsPath}`);
}

main().catch(err => console.error(err));
