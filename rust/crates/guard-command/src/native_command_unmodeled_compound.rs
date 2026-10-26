//! Launches and values inside compound text the parser leaves uncertain, each
//! read as the same words standing on their own: a launch behind a redirect
//! into a literal path, an inline program run from a list or a loop, a path
//! rooted at a quoted parameter, and a plain shell variable.
use super::prefix;
use super::redirections::without_redirections;
use super::{background_pipeline, literal_redirects_only, unquoted_literal};
use crate::pretool::PathContext;
use crate::CanonicalCommandV1;

/// Whether the only part of the command the parser could not read is a
/// redirect into a literal path, so the launch it carries is the one the same
/// text without that redirect runs.
///
/// `node server.js > /tmp/x.log 2>&1 &` runs what `node server.js &` runs and
/// sends its output to a file the text names. The redirect reason wins the
/// parser's scan, so the launch kept no segments, its script read as a file
/// nobody opened, and the dev server blocked outright with no approval left
/// to give it, while the same launch without the log file reached review. An
/// input redirect or a heredoc can feed the interpreter its program, and a
/// target the text does not spell could be anything, so both keep the
/// failure, as does a pipe a background job feeds.
pub(super) fn redirected_launch(command: &CanonicalCommandV1, context: PathContext<'_>) -> bool {
    let text = command.normalized_text.as_str();
    let bare = without_redirections(text);
    command.uncertainty_reason.as_deref() == Some("command_redirect_not_yet_supported")
        && command.wrapper_chain.is_empty()
        && !command.path_overridden
        && !unquoted_literal(text).contains('<')
        && literal_redirects_only(text)
        && !background_pipeline(&bare)
        && crate::pretool::models_exactly(&bare, context)
}

/// The inline program of every interpreter launch in a list or a loop, read
/// as each launch is read standing alone, or `None` when one of them is not
/// an inline program this scan reads.
///
/// `for f in a b; do [ -f "$f" ] && node -e '...' "$f"; done` runs the program
/// spelled between the quotes once per name. On its own, `node -e '...' "$f"`
/// is read and routed, but inside the loop the launch had no segments, so it
/// looked like an interpreter running a file nobody read and blocked outright.
/// A launch that names a script file, carries an environment of its own or
/// hands its program to a shell is still refused. So is any text that changes
/// directory or sources a file, since either moves where the program's
/// imports resolve from.
pub(super) fn listed_inline_sources(
    shell: &str,
    sources_files: bool,
    context: PathContext<'_>,
) -> Option<Vec<String>> {
    let commands: Vec<&str> = split_unquoted(shell, |character| {
        matches!(
            character,
            ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`'
        )
    })?
    .into_iter()
    .filter_map(past_reserved_words)
    .collect();
    if sources_files || commands.iter().any(|command| changes_directory(command)) {
        return None;
    }
    let mut sources = Vec::new();
    for launch in commands {
        if !prefix::interpreter_launch_reads_a_file(launch, false) {
            continue;
        }
        let request = serde_json::from_value(serde_json::json!({ "command": launch })).ok()?;
        let model = crate::parse_command(&request).ok()?;
        sources.extend(crate::pretool::sole_program_sources(&model, context)?);
    }
    (!sources.is_empty()).then_some(sources)
}

/// The text between the characters `split` picks out that stand outside
/// quotes, so an inline program such as `'console.log(a); b()'` stays whole.
/// `None` when a quote is left open.
fn split_unquoted(shell: &str, split: impl Fn(char) -> bool) -> Option<Vec<&str>> {
    let (mut pieces, mut start) = (Vec::new(), 0);
    let (mut single, mut double, mut escaped) = (false, false, false);
    for (index, character) in shell.char_indices() {
        if single {
            single = character != '\'';
        } else if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            double = !double;
        } else if !double && character == '\'' {
            single = true;
        } else if !double && split(character) {
            pieces.push(&shell[start..index]);
            start = index + character.len_utf8();
        }
    }
    pieces.push(&shell[start..]);
    (!single && !double && !escaped).then_some(pieces)
}

/// The command a list or loop piece runs, past the reserved words that only
/// say when it runs.
fn past_reserved_words(piece: &str) -> Option<&str> {
    let mut rest = piece.trim_start();
    loop {
        let (word, tail) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        if !matches!(
            word,
            "do" | "then" | "else" | "if" | "elif" | "while" | "until" | "!"
        ) {
            break;
        }
        rest = tail.trim_start();
    }
    let rest = rest.trim_end();
    (!rest.is_empty()).then_some(rest)
}

/// Whether the command, past the variables it sets, is one that moves the
/// shell to another directory, or a word that could expand to one.
fn changes_directory(command: &str) -> bool {
    let Some(words) = split_unquoted(command, char::is_whitespace) else {
        return true;
    };
    words
        .into_iter()
        .filter(|word| !word.is_empty())
        .find(|word| !sets_a_variable(word))
        .is_some_and(|word| {
            matches!(word.trim_matches(['\'', '"']), "cd" | "pushd" | "popd")
                || word.contains(['$', '\\'])
        })
}

fn sets_a_variable(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.chars()
            .next()
            .is_some_and(|first| !first.is_ascii_digit())
            && name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
    })
}

/// Whether every `$` in the text opens a parameter, inside double quotes,
/// that roots a path: `"$HOME/Downloads/x"` or `"${ROOT}/src"`.
///
/// `find "$HOME/Downloads/widgets" -type f -exec basename {} \;` searches a
/// directory under the home the shell already knows. The quotes keep the
/// value one word and the `/` after it keeps that word a path, so nothing the
/// value holds can become a find action, an operator or a program. Refusing
/// every `$` left that listing blocked outright, while the same search under
/// a relative root reached review.
pub(super) fn parameters_only_root_paths(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut index = 0;
    while let Some(&character) = chars.get(index) {
        index += 1;
        if single {
            single = character != '\'';
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '\'' if !double => single = true,
            '"' => double = !double,
            '$' => {
                let Some(after) = double
                    .then(|| rooted_parameter_end(&chars, index))
                    .flatten()
                else {
                    return false;
                };
                index = after;
            }
            _ => {}
        }
    }
    !single && !double
}

/// The index past `NAME` or `{NAME}` at `start`, when a `/` follows it.
fn rooted_parameter_end(chars: &[char], start: usize) -> Option<usize> {
    let braced = chars.get(start) == Some(&'{');
    let name = start + usize::from(braced);
    let length = chars[name.min(chars.len())..]
        .iter()
        .take_while(|character| character.is_ascii_alphanumeric() || **character == '_')
        .count();
    if length == 0 || chars[name].is_ascii_digit() {
        return None;
    }
    let mut end = name + length;
    if braced {
        (chars.get(end) == Some(&'}')).then_some(())?;
        end += 1;
    }
    (chars.get(end) == Some(&'/')).then_some(end)
}

/// `nodepath="$HOME/.nvm/..."`: a plain shell variable the text sets for its
/// own later words.
///
/// A lowercase name is not one the programs a command runs read from their
/// environment, and `ordinary_name` refuses the ones a shell ties to its own
/// state (zsh's `path`, `cdpath` and `fpath`) or that name a proxy, a package
/// manager setting or a credential. Any substitution in the value is still
/// data movement, and a command word built from the variable is refused
/// wherever it stands, so the text still names every program it runs.
pub(super) fn binds_a_shell_variable(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.chars().any(|character| character.is_ascii_lowercase())
            && crate::pretool::generic::chain_literals::ordinary_name(name)
    })
}

#[cfg(test)]
#[path = "native_command_unmodeled_compound_tests.rs"]
mod tests;
