use super::{SimpleCommand, effective_argv, simple_commands};

fn argvs(input: &str) -> Vec<Vec<String>> {
    simple_commands(input).into_iter().map(|c| c.argv).collect()
}

fn v(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_string()).collect()
}

#[test]
fn plain_command() {
    assert_eq!(argvs("ssh pi uptime"), vec![v(&["ssh", "pi", "uptime"])]);
}

#[test]
fn operators_split_commands() {
    assert_eq!(
        argvs("cd d && ssh pi | tee log; ls"),
        vec![
            v(&["cd", "d"]),
            v(&["ssh", "pi"]),
            v(&["tee", "log"]),
            v(&["ls"])
        ]
    );
}

#[test]
fn newline_and_background_split_commands() {
    assert_eq!(
        argvs("a &\nb || c |& d"),
        vec![v(&["a"]), v(&["b"]), v(&["c"]), v(&["d"])]
    );
}

#[test]
fn leading_assignments_are_env() {
    let cmds = simple_commands("SSH_AUTH_SOCK=/x ssh h");
    assert_eq!(cmds.len(), 1);
    assert_eq!(
        cmds[0].env,
        vec![("SSH_AUTH_SOCK".to_string(), "/x".to_string())]
    );
    assert_eq!(cmds[0].argv, v(&["ssh", "h"]));
}

#[test]
fn bash_c_recurses() {
    assert_eq!(
        argvs("bash -c 'ssh pi'"),
        vec![v(&["bash", "-c", "ssh pi"]), v(&["ssh", "pi"])]
    );
}

#[test]
fn bash_c_after_prefixes_recurses() {
    assert_eq!(
        argvs("sudo env A=1 sh -c 'ssh pi'"),
        vec![
            v(&["sudo", "env", "A=1", "sh", "-c", "ssh pi"]),
            v(&["ssh", "pi"])
        ]
    );
}

#[test]
fn bash_c_recurses_once() {
    assert_eq!(
        argvs("bash -c \"bash -c 'ssh pi'\""),
        vec![
            v(&["bash", "-c", "bash -c 'ssh pi'"]),
            v(&["bash", "-c", "ssh pi"])
        ]
    );
}

#[test]
fn command_substitution_is_recursed() {
    assert_eq!(
        argvs("x=$(op read op://v/i/f)"),
        vec![v(&["op", "read", "op://v/i/f"])]
    );
}

#[test]
fn backticks_are_recursed() {
    assert_eq!(
        argvs("echo `ssh pi`"),
        vec![v(&["echo", "ssh pi"]), v(&["ssh", "pi"])]
    );
}

#[test]
fn substitution_in_double_quotes_is_recursed() {
    assert_eq!(
        argvs("echo \"a $(ssh pi) b\""),
        vec![v(&["echo", "a ssh pi b"]), v(&["ssh", "pi"])]
    );
}

#[test]
fn nested_substitution_depth_is_limited() {
    let mut s = String::from("ssh pi");
    for _ in 0..6 {
        s = format!("echo $({s})");
    }
    let cmds = argvs(&s);
    assert_eq!(cmds.len(), 5, "outer command plus four levels");
}

#[test]
fn single_quotes_hide_operators() {
    assert_eq!(argvs("echo 'ssh pi'"), vec![v(&["echo", "ssh pi"])]);
    assert_eq!(argvs("ssh pi 'a; b'"), vec![v(&["ssh", "pi", "a; b"])]);
}

#[test]
fn quotes_join_inside_a_word() {
    assert_eq!(argvs("\"ss\"h pi"), vec![v(&["ssh", "pi"])]);
}

#[test]
fn backslash_escapes() {
    assert_eq!(argvs(r"ssh\ pi a\;b"), vec![v(&["ssh pi", "a;b"])]);
    assert_eq!(argvs("s\\\nsh pi"), vec![v(&["ssh", "pi"])]);
}

#[test]
fn heredoc_body_is_skipped() {
    assert_eq!(argvs("cat <<EOF\nssh pi\nEOF"), vec![v(&["cat"])]);
    assert_eq!(
        argvs("cat <<-'EOF'\n\tssh pi\n\tEOF\nls"),
        vec![v(&["cat"]), v(&["ls"])]
    );
    assert_eq!(
        argvs("cat <<\"E F\"\nssh pi\nE F\nls"),
        vec![v(&["cat"]), v(&["ls"])]
    );
}

#[test]
fn unterminated_heredoc_does_not_panic() {
    assert_eq!(argvs("cat <<EOF\nssh pi"), vec![v(&["cat"])]);
    assert_eq!(argvs("cat <<"), vec![v(&["cat"])]);
}

#[test]
fn comments_are_dropped() {
    assert_eq!(
        argvs("ls # ssh pi\nls a#b"),
        vec![v(&["ls"]), v(&["ls", "a#b"])]
    );
}

#[test]
fn redirections_are_dropped() {
    assert_eq!(argvs("ssh pi >out 2>&1 <in"), vec![v(&["ssh", "pi"])]);
    assert_eq!(argvs("ssh pi 2> err &>all >> log"), vec![v(&["ssh", "pi"])]);
    assert_eq!(argvs("cat <<< hi"), vec![v(&["cat"])]);
}

#[test]
fn subshell_parentheses_split() {
    assert_eq!(
        argvs("(cd d; ssh pi)"),
        vec![v(&["cd", "d"]), v(&["ssh", "pi"])]
    );
}

#[test]
fn unterminated_input_is_best_effort() {
    assert_eq!(argvs("ssh 'pi"), vec![v(&["ssh", "pi"])]);
    assert_eq!(argvs("ssh \"pi"), vec![v(&["ssh", "pi"])]);
    assert_eq!(
        argvs("echo $(ssh pi"),
        vec![v(&["echo", "ssh pi"]), v(&["ssh", "pi"])]
    );
    assert_eq!(
        argvs("echo `ssh pi"),
        vec![v(&["echo", "ssh pi"]), v(&["ssh", "pi"])]
    );
    assert_eq!(argvs("ssh pi \\"), vec![v(&["ssh", "pi"])]);
}

#[test]
fn empty_and_odd_input() {
    assert_eq!(argvs(""), Vec::<Vec<String>>::new());
    assert_eq!(argvs("   ;; && |"), Vec::<Vec<String>>::new());
    assert_eq!(argvs("echo ''"), vec![v(&["echo", ""])]);
    assert_eq!(argvs("A=1"), Vec::<Vec<String>>::new());
    let _ = argvs("$((1+2)) $( ) `` ${x");
    let _ = argvs("é ü 日本語 <<é\nx\né");
}

fn cmd(words: &[&str]) -> SimpleCommand {
    SimpleCommand {
        env: Vec::new(),
        argv: v(words),
    }
}

#[test]
fn effective_argv_strips_prefixes() {
    let c = cmd(&["sudo", "-u", "root", "ssh", "pi"]);
    assert_eq!(effective_argv(&c), v(&["ssh", "pi"]).as_slice());
    let c = cmd(&["env", "-i", "A=1", "B=2", "nohup", "time", "ssh", "pi"]);
    assert_eq!(effective_argv(&c), v(&["ssh", "pi"]).as_slice());
    let c = cmd(&["/usr/bin/sudo", "exec", "command", "ssh"]);
    assert_eq!(effective_argv(&c), v(&["ssh"]).as_slice());
    let c = cmd(&["sudo", "--", "-weird"]);
    assert_eq!(effective_argv(&c), v(&["-weird"]).as_slice());
}

#[test]
fn effective_argv_leaves_other_commands_alone() {
    let c = cmd(&["ssh", "sudo"]);
    assert_eq!(effective_argv(&c), v(&["ssh", "sudo"]).as_slice());
    assert_eq!(effective_argv(&cmd(&[])), &[] as &[String]);
    assert_eq!(effective_argv(&cmd(&["sudo", "-n"])), &[] as &[String]);
}

fn has(input: &str, words: &[&str]) -> bool {
    argvs(input).contains(&v(words))
}

#[test]
fn reserved_words_do_not_hide_the_command() {
    for (i, input) in [
        "{ ssh pi; }",
        "for h in a b; do ssh pi; done",
        "if ssh pi true; then ls; fi",
        "! ssh pi",
        "while ssh pi true; do :; done",
        "until ssh pi; do :; done",
        "if a; then b; elif ssh pi; then c; else ssh pi; fi",
        "f() { ssh pi; }",
        "case x in a) ssh pi;; esac",
        "select h in a b; do ssh pi; done",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            argvs(input)
                .iter()
                .any(|a| a.first().is_some_and(|w| w == "ssh")),
            "case {i}"
        );
    }
    assert!(has(
        "for h in a b; do ssh $h uptime; done",
        &["ssh", "$h", "uptime"]
    ));
    assert!(has("if ssh pi true; then ls; fi", &["ssh", "pi", "true"]));
    assert!(has("f() { ssh pi; }", &["ssh", "pi"]));
    assert!(has("case x in a) ssh pi;; esac", &["ssh", "pi"]));
}

#[test]
fn control_flow_headers_are_not_commands() {
    assert_eq!(argvs("for h in a b; do ls; done"), vec![v(&["ls"])]);
    assert_eq!(argvs("f() { ls; }"), vec![v(&["ls"])]);
    assert_eq!(argvs("function f { ssh pi; }"), vec![v(&["ssh", "pi"])]);
}

#[test]
fn quoted_reserved_words_are_words() {
    assert_eq!(argvs("'!' ssh"), vec![v(&["!", "ssh"])]);
}

#[test]
fn eval_recurses_once() {
    assert!(has("eval \"ssh pi\"", &["ssh", "pi"]));
    assert!(has("eval ssh pi", &["ssh", "pi"]));
    assert!(has("sudo eval ssh pi", &["ssh", "pi"]));
    assert_eq!(argvs("eval \"eval 'ssh pi'\"").len(), 2, "no second level");
}

#[test]
fn arithmetic_command_is_skipped() {
    assert_eq!(
        argvs("(( y = 1 << 2 ))\nssh pi uptime"),
        vec![v(&["ssh", "pi", "uptime"])]
    );
    assert_eq!(
        argvs("((cd d); ssh pi)"),
        vec![v(&["cd", "d"]), v(&["ssh", "pi"])]
    );
    let _ = argvs("((");
    let _ = argvs("(((");
}

#[test]
fn shell_options_before_c_are_scanned() {
    assert!(has("bash -o pipefail -c 'ssh pi'", &["ssh", "pi"]));
    assert!(has("bash +x -c 'ssh pi'", &["ssh", "pi"]));
    assert!(has("bash +o errexit -c 'ssh pi'", &["ssh", "pi"]));
    assert!(has("bash -e -x -c 'ssh pi'", &["ssh", "pi"]));
    assert!(has("sh -ec 'ssh pi'", &["ssh", "pi"]));
    assert!(has("bash -lc 'ssh pi'", &["ssh", "pi"]));
    assert_eq!(argvs("bash script.sh -c 'ssh pi'").len(), 1);
}

#[test]
fn wrapper_option_values_are_skipped() {
    for (input_index, (input, expected)) in [
        ("sudo --user root ssh pi", true),
        ("sudo -u root ssh pi", true),
        ("sudo --group wheel --chdir /x ssh pi", true),
        ("exec -a name ssh pi", true),
        ("env -u X ssh pi", true),
        ("env -C /x ssh pi", true),
        ("time -f %e ssh pi", true),
        ("time -o out ssh pi", true),
        ("sudo -u root", false),
    ]
    .into_iter()
    .enumerate()
    {
        let c = simple_commands(input).remove(0);
        assert_eq!(
            effective_argv(&c) == v(&["ssh", "pi"]).as_slice(),
            expected,
            "case {input_index}"
        );
    }
}

#[test]
fn env_split_string_recurses() {
    assert!(has("env -S 'ssh pi'", &["ssh", "pi"]));
    assert!(has("env --split-string 'ssh pi'", &["ssh", "pi"]));
    assert!(has("env --split-string='ssh pi'", &["ssh", "pi"]));
}

#[test]
fn command_lookup_runs_nothing() {
    for (i, input) in ["command -v op", "command -V op", "sudo command -v op"]
        .into_iter()
        .enumerate()
    {
        let c = simple_commands(input).remove(0);
        assert!(effective_argv(&c).is_empty(), "case {i}");
    }
    let c = simple_commands("command -p ssh pi").remove(0);
    assert_eq!(effective_argv(&c), v(&["ssh", "pi"]).as_slice());
}

#[test]
fn every_short_string_over_shell_characters_is_handled() {
    const ALPHABET: [char; 13] = [
        'a', ' ', '\'', '"', '\\', '$', '(', ')', '`', '<', '\n', '#', '-',
    ];
    let mut inputs = vec![String::new()];
    let mut start = 0;
    for _ in 0..5 {
        let end = inputs.len();
        for i in start..end {
            for c in ALPHABET {
                let mut next = inputs[i].clone();
                next.push(c);
                inputs.push(next);
            }
        }
        start = end;
    }
    for input in &inputs {
        let _ = simple_commands(input);
    }
}

#[test]
fn arithmetic_commands_are_still_skipped() {
    let cmds = simple_commands("((i = 1 + 2)); ssh pi");
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].argv, v(&["ssh", "pi"]));
    assert!(argvs("((x) ssh pi").contains(&v(&["ssh", "pi"])));
}

#[test]
fn long_runs_of_parentheses_return() {
    // No timing assertion: the scan is one forward pass, and a quadratic
    // one would make this test visibly slow rather than fail it.
    let open = "(".repeat(64 * 1024);
    let _ = simple_commands(&open);
    let pairs = "(( ".repeat(21_845);
    let _ = simple_commands(&pairs);
    let mixed = "((".repeat(32 * 1024);
    let _ = simple_commands(&mixed);
}

#[test]
fn arithmetic_skip_ignores_quotes_before_it() {
    for (i, input) in [
        "(( y = 1 << 2 ))\nssh pi uptime",
        "# don't\n(( y = 1 << 2 ))\nssh pi uptime",
        "cat <<EOF\ndon't\nEOF\n(( y = 1 << 2 ))\nssh pi uptime",
    ]
    .iter()
    .enumerate()
    {
        assert!(
            argvs(input).contains(&v(&["ssh", "pi", "uptime"])),
            "case {i}"
        );
    }
}
