// Q-44: reviewed canonical executable names for the Hosted SHADOW request.
//
// The executable word of a command can itself be a secret (for example a
// pasted access key run as a command). Only names in this reviewed list are
// transmitted verbatim, and only by exact, case-sensitive match of the command
// word's basename. Every other executable — scripts, project binaries, paths,
// typos, anything secret-like — is transmitted only as the coarse class
// EXECUTABLE_CLASS_UNLISTED. Membership is not a credential-prefix heuristic:
// unknown means unlisted, whatever it looks like.
//
// Criteria for this list: widely distributed, publicly documented command-line
// tools whose names carry no user, host or secret information. `touch` and
// `mkdir` are the names the Hosted baseline policy lanes match on
// (pb.observa.openclaw-shadow.exec-baseline). Changing this list changes Hosted
// evaluation inputs and requires review.
export const EXECUTABLE_CLASS_UNLISTED = "observa:unlisted-executable";

export const CANONICAL_EXECUTABLES = Object.freeze(new Set([
  // POSIX / coreutils / common userland
  "awk", "basename", "bash", "cat", "cd", "chmod", "chown", "cmp", "comm", "cp",
  "cut", "date", "dd", "df", "diff", "dirname", "du", "echo", "env", "expr",
  "false", "file", "find", "grep", "egrep", "fgrep", "gzip", "gunzip", "head",
  "hostname", "id", "kill", "less", "ln", "ls", "md5sum", "mkdir", "mktemp",
  "more", "mv", "nl", "nohup", "od", "paste", "printf", "ps", "pwd", "readlink",
  "realpath", "rm", "rmdir", "sed", "seq", "sh", "sha1sum", "sha256sum",
  "shasum", "sleep", "sort", "split", "stat", "tail", "tar", "tee", "test",
  "time", "timeout", "touch", "tr", "true", "type", "uname", "uniq", "unzip",
  "wc", "which", "whoami", "xargs", "yes", "zip", "zsh", "command", "export",
  "source", "xxd", "base64", "jq", "yq", "tree", "rsync", "lsof", "top",
  // Network clients
  "curl", "wget", "ssh", "scp", "sftp", "ping", "dig", "nslookup", "nc",
  // Version control and build
  "git", "gh", "make", "cmake", "gcc", "g++", "clang", "cc", "c++", "go",
  "cargo", "rustc", "javac", "java", "mvn", "gradle",
  // Language runtimes and package managers
  "node", "npm", "npx", "pnpm", "yarn", "bun", "deno", "python", "python3",
  "pip", "pip3", "uv", "pipx", "poetry", "ruby", "gem", "bundle", "perl",
  "php", "composer", "dotnet",
  // Containers, cloud and data CLIs
  "docker", "podman", "kubectl", "helm", "terraform", "aws", "gcloud", "az",
  "psql", "mysql", "sqlite3", "redis-cli",
  // Agent-runtime adjacent
  "openclaw", "observa", "clawhub",
]));

export function canonicalExecutable(basename) {
  return CANONICAL_EXECUTABLES.has(basename) ? basename : EXECUTABLE_CLASS_UNLISTED;
}
