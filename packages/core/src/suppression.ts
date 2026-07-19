export function isSuppressedSourceLine(line: string): boolean {
  return line.includes('scanner-ignore:');
}
