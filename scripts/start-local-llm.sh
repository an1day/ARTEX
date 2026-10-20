#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
config_path="${ARTEX_LOCAL_LLM_CONFIG:-.env.llm.local}"
if [[ ! -f "$config_path" ]]; then
  echo "Create .env.llm.local from .env.llm.example and inject your key locally." >&2
  exit 1
fi
# Read literal assignments without evaluating shell code or printing values.
while IFS= read -r entry || [[ -n "$entry" ]]; do
  entry="${entry%$'\r'}"
  case "$entry" in ''|'#'*) continue ;; esac
  if [[ "$entry" != *=* ]]; then echo "Invalid LLM setting" >&2; exit 1; fi
  env_name="${entry%%=*}"
  env_value="${entry#*=}"
  case "$env_name" in
    ARTEX_LLM_PROVIDER|ARTEX_LLM_BASE_URL|ARTEX_LLM_MODEL|ANTHROPIC_API_KEY|ARTEX_LLM_STREAM)
      export "$env_name=$env_value" ;;
    *) echo "Unsupported local LLM setting" >&2; exit 1 ;;
  esac
done < "$config_path"
mode="${1:-backend}"
if [[ $# -gt 0 ]]; then shift; fi
case "$mode" in
  smoke) exec go run ./cmd/artex-llm-smoke "$@" ;;
  backend) exec go run ./cmd/artex -addr 127.0.0.1:8787 "$@" ;;
  *) echo "Usage: bash scripts/start-local-llm.sh [backend|smoke]" >&2; exit 1 ;;
esac
