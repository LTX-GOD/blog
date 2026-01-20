import { createHash } from 'crypto';

export function getCodeHash(code: string, lang: string, theme: string): string {
  const hash = createHash('md5');
  hash.update(`${code}|${lang}|${theme}`);
  return hash.digest('hex');
}
