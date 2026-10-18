# Source this only after adverserial-confidential-gateway is listening locally.
: "${ADVERSERIAL_API_KEY:?Set ADVERSERIAL_API_KEY before starting Claude Code.}"
export ANTHROPIC_BASE_URL='http://127.0.0.1:8787'
# Claude Code accepts either bearer-token gateway auth or an API key depending
# on its mode. The loopback gateway accepts both and never forwards this key to
# the runtime.
export ANTHROPIC_AUTH_TOKEN="$ADVERSERIAL_API_KEY"
export ANTHROPIC_API_KEY="$ADVERSERIAL_API_KEY"
# Claude Code chooses models for background agents and auxiliary requests
# independently of the interactive session. Pin every documented role to the
# same canonical confidential runtime so they inherit the verified route.
export ANTHROPIC_MODEL='lordx64/cyberglm'
export ANTHROPIC_DEFAULT_OPUS_MODEL='lordx64/cyberglm'
export ANTHROPIC_DEFAULT_SONNET_MODEL='lordx64/cyberglm'
export ANTHROPIC_DEFAULT_HAIKU_MODEL='lordx64/cyberglm'
export ANTHROPIC_DEFAULT_FABLE_MODEL='lordx64/cyberglm'
export ANTHROPIC_SMALL_FAST_MODEL='lordx64/cyberglm'
export ANTHROPIC_CUSTOM_MODEL_OPTION='lordx64/cyberglm'
export ANTHROPIC_CUSTOM_MODEL_OPTION_NAME='CyberGLM — verified confidential runtime'
export CLAUDE_CODE_ENABLE_FINE_GRAINED_TOOL_STREAMING=1
