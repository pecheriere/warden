# warden plugin for Claude Code

This plugin wires two Claude Code hooks to the `warden` command. It holds no
instructions and no patterns of its own: everything it says and checks comes from
the installed `warden`, so it never drifts from it.

| Hook | Runs | Timeout |
|---|---|---|
| `SessionStart` (startup, resume, clear and compact) | `warden hook session-start` | 5 s |
| `PreToolUse`, matcher `Bash` | `warden hook check` | 2 s |

The first starts each session with what warden offers this machine. The second
looks at a shell command before it runs and answers when it goes around warden.
What each case does is set in the `[hook]` table of warden's configuration.

## Not a security boundary

The hook catches honest mistakes. The agent runs as the same user, can edit the
configuration and can obfuscate a command. The hook sees only the Bash tool, not
the other tools. See "Agent hooks" in
[docs/agent-usage.md](../../docs/agent-usage.md#agent-hooks).

## Install

```sh
warden setup claude
```

This adds the marketplace pinned to the tag of your `warden` version, installs
the plugin and updates it. By hand, the same thing is:

```sh
claude plugin marketplace add pecheriere/warden#v<version> --scope user
claude plugin install warden@warden --scope user
claude plugin update warden@warden --scope user
```

`#<ref>` after `owner/repo` pins a branch or tag (`owner/repo@ref` is accepted
too), and a pinned marketplace stays on that tag until you add another. Claude
Code documents this under "Add a marketplace" in its plugin commands reference
and in "Host and distribute marketplaces". Adding the `warden` marketplace again
points it at the new tag, and the update moves an installed plugin there, so
after upgrading `warden`, run `warden setup claude` again.

## Requirements

`warden` on the `PATH`, at least the plugin's version (`version` in
`.claude-plugin/plugin.json`, kept equal to the workspace version by
`scripts/check-plugin-version.sh`). The plugin first works from the release that
contains it.

If `warden` is missing (status 127), or is 0.9.0 to 0.15.0, which does not know
`hook` and exits 64, Claude Code treats that as a non-blocking error: it shows a
hook error and the session or tool call goes on. A `warden` older than 0.9.0
exits 2 on an unknown subcommand, which Claude Code reads as a block, so every
Bash call is refused. Upgrade it, and make sure the `warden` on Claude Code's
`PATH` is the one that ran `warden setup claude`.
