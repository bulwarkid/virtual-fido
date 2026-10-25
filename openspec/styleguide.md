# Style Guide

This style guide is based on the [LND styleguide](https://github.com/lightningnetwork/lnd/blob/master/.gemini/styleguide.md).

## Go Style

### Switch Statements
**WRONG**
```go
switch {
case a:
case b: case c: case d:
default:
}
```

**RIGHT**
```go
switch {
// Brief comment detailing instances of this case (repeat below).
case a:

case b:
case c:
case d:

default:
}
```

### 80 character line length
- Wrap columns at 80 characters.
- Tabs are 8 spaces.

**WRONG**
```go
myKey := "0214cd678a565041d00e6cf8d62ef8add33b4af4786fb2beb87b366a2e151fcee7"
```

**RIGHT**
```go
myKey := "0214cd678a565041d00e6cf8d62ef8add33b4af4786fb2beb87b366a2e1" +
	"51fcee7"
```

### Wrapping long function calls
- If a function call exceeds the column limit, place the closing parenthesis on its own line and start all arguments on a new line after the opening parenthesis.

**WRONG**
```go
value, err := bar(a, a, b, c)
```

**RIGHT**
```go
value, err := bar(
	a,
	a,
	b,
	c,
)
```

- Compact form is acceptable if visual symmetry of parentheses is preserved.

**ACCEPTABLE**
```go
response, err := node.AddInvoice(
	ctx,
	&lnrpc.Invoice{
		Memo:      "invoice",
		ValueMsat: int64(oneUnitMilliSat - 1),
	},
)
```

**PREFERRED**
```go
response, err := node.AddInvoice(ctx, &lnrpc.Invoice{
	Memo:      "invoice",
	ValueMsat: int64(oneUnitMilliSat - 1),
})
```

### Exception for log and error message formatting
- Minimize lines for log and error messages, while adhering to the 80-character limit.

**WRONG**
```go
return fmt.Errorf(
	"this is a long error message with a couple (%d) place holders",
	len(things),
)

log.Debugf(
	"Something happened here that we need to log: %v",
	longVariableNameHere,
)
```

**RIGHT**
```go
return fmt.Errorf("this is a long error message with a couple (%d) place "+
	"holders", len(things))

log.Debugf("Something happened here that we need to log: %v", longVariableNameHere)
```

### Exceptions and additional styling for structured logging
- **Static messages:** Use key-value pairs instead of formatted strings for the `msg` parameter.
- **Key-value attributes:** Use `slog.Attr` helper functions.
- **Line wrapping:** Structured log lines are an exception to the 80-character rule. Use one line per key-value pair for multiple attributes.

**WRONG**
```go
log.DebugS(ctx, fmt.Sprintf("User %d just spent %.8f to open a channel", userID, 0.0154))
```

**RIGHT**
```go
log.InfoS(ctx, "Channel open performed",
	slog.Int("user_id", userID),
	btclog.Fmt("amount", "%.8f", 0.00154))
```

### Wrapping long function definitions
- If function arguments exceed the 80-character limit, maintain indentation on following lines.
- Do not end a line with an open parenthesis if the function definition is not finished.

**WRONG**
```go
func foo(a, b, c,
) (d, error) {

func bar(a, b, c) (
	d,
	error,
) {

func baz(a, b, c) (
	d, error) {
```

**RIGHT**
```go
func foo(a, b, c) (d, error) {

func baz(a, b, c) (d, error) {

func longFunctionName(
	a, b, c) (d, error) {
```

- If a function declaration spans multiple lines, the body should start with an empty line.

**WRONG**
```go
func foo(a, b, c, d, e) error {
	var a int
}
```

**RIGHT**
```go
func foo(a, b, c, d, e) error {

	var a int
}
```

## Use of Log Levels
- Available levels: `trace`, `debug`, `info`, `warn`, `error`, `critical`.
- Only use `error` for internal errors not triggered by external sources.

## Testing
- To run all tests for a specific package: `make unit pkg=$pkg`
- To run a specific test case within a package: `make unit pkg=$pkg case=$case`

## Git Commit Messages
- **Subject Line:**
	- Format: `subsystem: short description of changes`
	- `subsystem` should be the package primarily affected (e.g., `lnwallet`, `rpcserver`).
	- For multiple packages, use `+` or `,` as a delimiter (e.g., `lnwallet+htlcswitch`).
	- For widespread changes, use `multi:`.
	- Keep it under 50 characters.
	- Use the present tense (e.g., "Fix bug", not "Fixed bug").
- **Message Body:**
	- Separate from the subject with a blank line.
	- Explain the "what" and "why" of the change.
	- Wrap text to 72 characters.
	- Use bullet points for lists.
