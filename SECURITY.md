# Security and responsible use

## Authorized use only

CoerceProbe is a security-testing tool. It causes Windows hosts to initiate
authentication to a listener you control and can generate alerts, lockouts, or
service disruption.

By using this software you confirm that:

1. You have **written authorization** for every target and the engagement.
2. Your activity stays within the agreed scope, time window, and rules of
   engagement.
3. You will comply with all applicable laws and contractual obligations.
4. You accept sole responsibility for your actions and any consequences.

The author (`kalraji007`) accepts no liability for misuse, damage, or legal
consequences.

## Do not use on systems you do not own or have permission to test

This includes public IP addresses, third-party cloud tenants, and any system
where you are not an authorized tester.

## Reporting a problem

If you find a bug that could cause unintended impact (for example, a method
that writes to a target rather than only triggering authentication), open a
private security advisory on the repository or contact the maintainer directly.
Do not include live credentials, customer data, or target identifiers in a
public issue.

## Data handling

- Prefer `--password` omitted (interactive prompt) over command-line secrets.
- Captured NetNTLMv2 material is sensitive; protect `--capture-log` files.
- Do not commit captures, target lists, or engagement evidence to the repo.
- `.gitignore` excludes common local artifacts, but you are responsible for
  checking before publishing.
