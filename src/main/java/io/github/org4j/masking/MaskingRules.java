package io.github.org4j.masking;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * What {@link Masking} hides, and how. The library defines no name or pattern of its own: every
 * rule comes from its user.
 *
 * <p>Names are compared ignoring case, and a dotted name also matches by its last part: a rule for
 * {@code key} hides {@code a.key}. The constructor normalizes the names (trimmed, lower case,
 * blanks dropped) and copies every collection, so the rules are immutable.
 *
 * {@snippet :
 * new MaskingRules(
 *     ".",
 *     Set.of("account"),                                     // 123456......3456
 *     Set.of("password", "secret"),                          // ......
 *     List.of(Pattern.compile("(?<!\\d)\\d{13,19}(?!\\d)"))); // a long number anywhere
 * }
 *
 * @param maskChar the character that replaces hidden ones; {@value
 *     MaskingConstants#DEFAULT_MASK_CHAR} when blank
 * @param fields names whose values take the {@linkplain Masking#maskValue base hook}
 * @param fullFields names whose values are {@linkplain Masking#maskWhole hidden whole}; a name in
 *     both sets is hidden whole
 * @param values patterns for values found anywhere, with no name around them; every match takes the
 *     base hook
 */
public record MaskingRules(
    String maskChar, Set<String> fields, Set<String> fullFields, List<Pattern> values) {

  /** Normalizes the names and copies every collection. */
  public MaskingRules {
    maskChar =
        (maskChar == null || maskChar.isBlank()) ? MaskingConstants.DEFAULT_MASK_CHAR : maskChar;
    fields = normalized(fields);
    fullFields = normalized(fullFields);
    values = List.copyOf(values);
  }

  /**
   * Returns rules that hide nothing.
   *
   * @return rules with no name and no pattern
   */
  public static MaskingRules empty() {
    return of(List.of());
  }

  /**
   * Returns rules with base-hook names only and the default mask character.
   *
   * @param fields names whose values take the base hook
   * @return the rules
   */
  public static MaskingRules of(Collection<String> fields) {
    return new MaskingRules(
        MaskingConstants.DEFAULT_MASK_CHAR, Set.copyOf(fields), Set.of(), List.of());
  }

  /**
   * Tells whether these rules hide nothing.
   *
   * @return {@code true} when there is no name and no pattern
   */
  public boolean isEmpty() {
    return fields.isEmpty() && fullFields.isEmpty() && values.isEmpty();
  }

  /**
   * Tells whether values under a name are hidden, by either set.
   *
   * @param fieldName the name, compared ignoring case and also by its last dotted part
   * @return {@code true} if the name is in {@link #fields} or {@link #fullFields}
   */
  public boolean contains(String fieldName) {
    return isIn(fields, fieldName) || isIn(fullFields, fieldName);
  }

  /**
   * Tells whether values under a name are hidden whole.
   *
   * @param fieldName the name, compared ignoring case and also by its last dotted part
   * @return {@code true} if the name is in {@link #fullFields}
   */
  public boolean masksWhole(String fieldName) {
    return isIn(fullFields, fieldName);
  }

  private static boolean isIn(Set<String> names, String fieldName) {
    var name = fieldName.toLowerCase(Locale.ROOT);
    var lastPart = name.substring(name.lastIndexOf('.') + 1);
    return names.contains(name) || names.contains(lastPart);
  }

  private static Set<String> normalized(Set<String> names) {
    return names.stream()
        .map(name -> name.strip().toLowerCase(Locale.ROOT))
        .filter(name -> !name.isEmpty())
        .collect(Collectors.toUnmodifiableSet());
  }
}
