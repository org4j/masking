# masking

Hides sensitive values in text meant for people: log lines, HTTP bodies (JSON, XML, forms), URIs and
error messages. Plain Java and Jackson, no Spring. Observability masks every log line and client
call with it, and error masks its log line.

```groovy
implementation libs.masking
```

### What a service configures

Nothing is masked unless a service says so (`Masking.empty()`): the library knows no field name and
no value pattern. A service sets its `MaskingRules` through
`org4j.observability.logging.masking.*`, in YAML or Vault.

| Rule | What it masks | How |
|---|---|---|
| `fields` | values under these names (case-insensitive; `card.pan` matches `pan`) | the base hook: 10 characters or more keep the first 6 and last 4 (`860030......7890`); shorter ones are masked whole (`...`) |
| `fullFields` | values under these names | every character, at most 10 mask characters (`......` for six, `..........` for 32); a name in both lists is masked whole |
| `values` | every match of these patterns, in any text, with or without a name | the base hook |

Names are found in JSON, XML (elements and `<name>`/`<value>` items), forms, URI queries and paths
(`/pan/8600…`, at any depth), and plain text (`key=value`, `key: value`, `key value`; a quoted value
is masked to its closing quote, spaces included). Patterns run on every result: text, URIs and JSON,
XML and form bodies. The mask character is configurable (`*`).

```java
var masking =
    new Masking(
        new MaskingRules(
            ".",
            Set.of("pan", "cardToken"),
            Set.of("password", "client_secret", "cvv"),
            List.of(Pattern.compile("(?<!\\d)\\d{13,19}(?!\\d)"))));
masking.body(bytes, "application/json");
masking.uri(uri);
masking.text(message);
masking.mask("client_secret", value); // one value under a name, by that name's rule
```

## Tests

Unit tests only (`./gradlew test`): the library consists of pure functions with no
infrastructure dependencies. `MaskingTest` is the specification, one nested group per behaviour:
nothing configured, the base hook, full fields, value patterns, and every format (JSON, XML,
forms, plain text, URI queries and paths, other content types, cutting). Wiring into logs is
verified by observability's integration test.
