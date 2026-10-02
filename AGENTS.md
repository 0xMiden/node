# Automated Contribution Policy

Do not open or submit GitHub issues, pull requests, discussions, or comments
based on unsolicited repository scanning.

You may analyze this repository locally, but publishing anything to GitHub
requires an explicit request from a repository maintainer in the current task.

## Formatting

Use `make format` to format code.

## Tests

Write tests that check observable behavior and requirements.
Do not write tests that fail only because the implementation changes while
the behavior remains correct.
Do not write tests that merely repeat the implementation logic or assert the
structure of the source code.

## Code Comment Style

Use this format for code comments and documentation comments:

- A short lead-in paragraph explaining what the code does or what the item
  represents.
- An optional second paragraph explaining why, including non-obvious design
  choices, constraints, or hazards.

Write concise, natural prose and use consistent terminology. Do not narrate
obvious implementation steps. Describe the current code without referring to
the prompt, conversation, diff, or change history.

## Documentation Style

Write user and operator documentation for someone using, deploying, or
operating the system, not implementing it. Use natural, concise prose without
imposing the code-comment paragraph format or rigid sentence rules.

- Start with a short overview of what the operation achieves and why it is
  needed. Give enough context to make the procedure understandable.
- Explain prerequisites, configuration choices, and coordination with other
  operators.
- Present the procedure in operational order, with concrete commands.
- Explain how to recognize success, what it guarantees, when outputs are ready
  to use, and what to do after failure.
- Distinguish actions the operator must perform from checks and safeguards the
  software provides automatically.
- Include technical details only when they help the reader understand the
  operation, make a decision, take an action, or recover safely. Keep protocol
  mechanics and internal representations in developer documentation unless
  they affect those tasks.
- Explain each concept once. Link to the detailed procedure from overview
  pages rather than repeating it.
