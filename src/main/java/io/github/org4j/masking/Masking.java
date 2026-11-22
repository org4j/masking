package io.github.org4j.masking;

import static io.github.org4j.masking.MaskingConstants.AMPERSAND;
import static io.github.org4j.masking.MaskingConstants.KEY_COLON;
import static io.github.org4j.masking.MaskingConstants.KEY_EQUALS;
import static io.github.org4j.masking.MaskingConstants.KEY_PATH;
import static io.github.org4j.masking.MaskingConstants.KEY_SPACE;
import static io.github.org4j.masking.MaskingConstants.MAX_LENGTH;
import static io.github.org4j.masking.MaskingConstants.MAX_WHOLE_MASK;
import static io.github.org4j.masking.MaskingConstants.XML_ELEMENT;
import static io.github.org4j.masking.MaskingConstants.XML_ITEM;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.jspecify.annotations.Nullable;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Hides sensitive values in text meant for people: log lines, HTTP bodies, URIs and error messages.
 *
 * <p>A value is found by its <b>name</b>, a configured field in JSON, XML, a form, a URI or plain
 * text, or by its <b>form</b>, a configured pattern for a value with no name around it. A found
 * value is hidden one of two ways:
 *
 * <ul>
 *   <li><b>base hook</b> ({@link #maskValue}): a value of 10 characters or more keeps its first 6
 *       and last 4; a shorter one is hidden whole;
 *   <li><b>whole</b> ({@link #maskWhole}): every character is hidden, and at most 10 mask
 *       characters are shown.
 * </ul>
 *
 * <p>What is found and how it is hidden is set by {@link MaskingRules}; nothing is masked unless
 * the rules say so. Instances are immutable and thread-safe.
 *
 * {@snippet :
 * var masking =
 *     new Masking(new MaskingRules(".", Set.of("account"), Set.of("password"), List.of()));
 * masking.text("account=1234567890123456 password=s3cr3t");
 * // "account=123456......3456 password=......"
 * }
 *
 * @see MaskingRules
 */
public final class Masking {

  private final MaskingRules rules;

  /**
   * Creates a masking that applies the given rules.
   *
   * @param rules what to find and how to hide it
   */
  public Masking(MaskingRules rules) {
    this.rules = rules;
  }

  /**
   * Returns a masking that hides nothing: every method returns its input unchanged. The one to fall
   * back on when none is configured.
   *
   * @return a masking with {@linkplain MaskingRules#empty() empty rules}
   */
  public static Masking empty() {
    return new Masking(MaskingRules.empty());
  }

  /**
   * Tells whether any rule is configured.
   *
   * @return {@code false} when the rules are empty, in which case every method returns its input
   *     unchanged
   */
  public boolean isEnabled() {
    return !rules.isEmpty();
  }

  /**
   * Tells whether a name is configured, as a base-hook field or a whole field.
   *
   * <p>For a caller that formats names and values itself, such as HTTP headers: check this, then
   * hide the value with {@link #mask(String, String)}.
   *
   * @param fieldName a name as it appears in the text, compared ignoring case; a dotted name also
   *     matches by its last part ({@code a.key} matches {@code key})
   * @return {@code true} if values under this name are hidden
   */
  public boolean contains(String fieldName) {
    return rules.contains(fieldName);
  }

  /**
   * Hides one value the way its name is configured: {@link #maskWhole whole} for a whole field, the
   * {@link #maskValue base hook} otherwise.
   *
   * <p>This does not check that the name is configured; call {@link #contains} first.
   *
   * @param fieldName the name the value was found under
   * @param value the value to hide
   * @return the hidden value
   */
  public String mask(String fieldName, String value) {
    return rules.masksWhole(fieldName) ? maskWhole(value) : maskValue(value);
  }

  /**
   * Hides a value with the base hook: a value of 10 characters or more keeps its first 6 and last
   * 4, with one mask character for each hidden one; a shorter value is {@linkplain #maskWhole
   * hidden whole}. Surrounding whitespace is dropped first.
   *
   * {@snippet :
   * masking.maskValue("1234567890123456"); // "123456......3456"
   * masking.maskValue("1234");             // "...."
   * }
   *
   * @param value the value to hide
   * @return the hidden value
   */
  public String maskValue(String value) {
    var trimmed = value.strip();
    if (trimmed.length() < 10) {
      return maskWhole(trimmed);
    }
    var hidden = rules.maskChar().repeat(trimmed.length() - 10);
    return trimmed.substring(0, 6) + hidden + trimmed.substring(trimmed.length() - 4);
  }

  /**
   * Hides every character of a value. The result is the mask character repeated as many times as
   * the value is long, without surrounding whitespace, and at most 10 times, so a long value does
   * not reveal its length.
   *
   * {@snippet :
   * masking.maskWhole("s3cr3t");           // "......"
   * masking.maskWhole("0123456789abcdef"); // ".........."
   * }
   *
   * @param value the value to hide
   * @return the mask
   */
  public String maskWhole(String value) {
    return rules.maskChar().repeat(Math.min(value.strip().length(), MAX_WHOLE_MASK));
  }

  /**
   * Hides the values in free text, such as a log message or an exception message.
   *
   * <p>Values are found next to a configured name as {@code name=value}, {@code name="value"},
   * {@code name: value}, {@code "name":"value"}, {@code name value} and {@code /name/value}; only
   * the value changes. Then every configured pattern is applied to what is left.
   *
   * @param text the text to mask
   * @return the masked text; {@code null} for {@code null}, and the text unchanged when it is empty
   *     or no rule is configured
   */
  public @Nullable String text(@Nullable String text) {
    if (text == null || text.isEmpty() || rules.isEmpty()) {
      return text;
    }
    var named = namedPairs(KEY_SPACE, namedPairs(KEY_COLON, namedPairs(KEY_EQUALS, text)));
    return patterns(pathSegments(named));
  }

  /**
   * Hides the values in a URI: query parameters and path segments ({@code /name/value}) under a
   * configured name, then every configured pattern. Parameter names are compared decoded; values
   * are hidden as they were encoded.
   *
   * @param uri the URI to mask
   * @return the masked URI as text, or {@code uri.toString()} when no rule is configured
   */
  public String uri(URI uri) {
    var whole = uri.toString();
    if (rules.isEmpty()) {
      return whole;
    }
    var query = uri.getRawQuery();
    if (query == null) {
      return patterns(pathSegments(whole));
    }
    var start = whole.indexOf('?') + 1;
    var path = pathSegments(whole.substring(0, start));
    return patterns(path + formBody(query) + whole.substring(start + query.length()));
  }

  /**
   * Hides the values in an HTTP body, read as UTF-8 and parsed by its content type.
   *
   * <ul>
   *   <li>JSON (any subtype containing {@code json}): values under a configured name, at any depth;
   *       a {@code null} stays {@code null}. A body that does not parse is replaced by {@code <n
   *       characters, not JSON>}.
   *   <li>XML (any subtype containing {@code xml}): elements and {@code <name>}/{@code <value>}
   *       items under a configured name.
   *   <li>Forms ({@code application/x-www-form-urlencoded}): parameters under a configured name.
   *   <li>Any other type, or none: replaced by {@code <n bytes, type>}, since it cannot be searched
   *       by name.
   * </ul>
   *
   * <p>Every configured pattern is then applied, and a result longer than 4 000 characters is cut
   * and ends with {@code …}.
   *
   * @param body the body as sent
   * @param contentType the body's {@code Content-Type}, parameters allowed
   * @return the masked body; an empty string for a {@code null} or empty body, and the body
   *     unchanged and uncut when no rule is configured
   */
  public String body(byte @Nullable [] body, @Nullable String contentType) {
    if (body == null || body.length == 0) {
      return "";
    }
    var text = new String(body, StandardCharsets.UTF_8);
    if (rules.isEmpty()) {
      return text;
    }
    var subtype = subtype(contentType);
    if (subtype.contains("json")) {
      return shown(jsonBody(text));
    }
    if (subtype.contains("xml")) {
      return shown(xmlBody(text));
    }
    if (subtype.equals("x-www-form-urlencoded")) {
      return shown(formBody(text));
    }
    return "<" + body.length + " bytes" + (contentType == null ? "" : ", " + contentType) + ">";
  }

  private String shown(String masked) {
    var whole = patterns(masked);
    return whole.length() > MAX_LENGTH ? whole.substring(0, MAX_LENGTH) + "…" : whole;
  }

  private String jsonBody(String text) {
    try {
      var tree = JsonMapper.shared().readTree(text);
      maskJson(tree);
      return tree.toString();
    } catch (JacksonException e) {
      return "<" + text.length() + " characters, not JSON>";
    }
  }

  private void maskJson(JsonNode node) {
    if (node instanceof ObjectNode object) {
      for (var name : List.copyOf(object.propertyNames())) {
        var value = object.get(name);
        if (!value.isValueNode()) {
          maskJson(value);
        } else if (!value.isNull() && rules.contains(name)) {
          object.put(name, mask(name, value.asString()));
        }
      }
    } else if (node.isArray()) {
      node.forEach(this::maskJson);
    }
  }

  // Both patterns share their groups: opening, name, value, closing.
  private String xmlBody(String text) {
    return replace(XML_ELEMENT, replace(XML_ITEM, text, this::xmlValue), this::xmlValue);
  }

  private String xmlValue(MatchResult m) {
    var name = m.group(2);
    return rules.contains(name) ? m.group(1) + mask(name, m.group(3)) + m.group(4) : m.group();
  }

  // A name is compared decoded, a value is masked as sent.
  private String formBody(String text) {
    return AMPERSAND.splitAsStream(text).map(this::formParameter).collect(Collectors.joining("&"));
  }

  private String formParameter(String parameter) {
    var equals = parameter.indexOf('=');
    if (equals < 0) {
      return parameter;
    }
    var name = URLDecoder.decode(parameter.substring(0, equals), StandardCharsets.UTF_8);
    return rules.contains(name)
        ? parameter.substring(0, equals + 1) + mask(name, parameter.substring(equals + 1))
        : parameter;
  }

  // Only the value changes; the name, separator and quotes stay.
  private String namedPairs(Pattern shape, String text) {
    return replace(
        shape,
        text,
        m -> {
          var name = m.group(1);
          if (!rules.contains(name)) {
            return m.group();
          }
          var quote = m.group(3);
          return name + m.group(2) + quote + mask(name, m.group(4)) + quote;
        });
  }

  // A segment names the next one. An unmatched segment advances the search by one, not two, so a
  // name is found at any position.
  private String pathSegments(String text) {
    var matcher = KEY_PATH.matcher(text);
    var masked = new StringBuilder();
    var copied = 0;
    var from = 0;
    while (from < text.length() && matcher.find(from)) {
      var name = matcher.group(1);
      if (rules.contains(name)) {
        masked.append(text, copied, matcher.start(2)).append(mask(name, matcher.group(2)));
        copied = matcher.end(2);
        from = copied;
      } else {
        from = matcher.end(1);
      }
    }
    return masked.append(text, copied, text.length()).toString();
  }

  // Runs last, so a value already hidden by name is not matched again.
  private String patterns(String text) {
    var masked = text;
    for (var pattern : rules.values()) {
      masked = replace(pattern, masked, m -> maskValue(m.group()));
    }
    return masked;
  }

  private static String replace(
      Pattern pattern, String text, Function<MatchResult, String> replacement) {
    return pattern
        .matcher(text)
        .replaceAll(match -> Matcher.quoteReplacement(replacement.apply(match)));
  }

  // application/problem+json;charset=UTF-8 -> problem+json
  private static String subtype(@Nullable String contentType) {
    if (contentType == null) {
      return "";
    }
    var type = contentType.split(";", 2)[0].strip().toLowerCase(Locale.ROOT);
    return type.substring(type.indexOf('/') + 1);
  }
}
