/** Nur https://github.com/<owner>/<repo>(.git) ist zulässig. */
export const GITHUB_REPO_RE = /^https:\/\/github\.com\/([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?\/?$/;

export function parseGithubUrl(url: string): { owner: string; repo: string } | null {
  const m = url.match(GITHUB_REPO_RE);
  if (!m || m[2] === "." || m[2] === "..") return null;
  return { owner: m[1]!, repo: m[2]! };
}
