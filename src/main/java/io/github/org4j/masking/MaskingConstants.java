package io.github.org4j.masking;

import java.util.regex.Pattern;

/** Constants shared by {@link Masking} and {@link MaskingRules}. */
// The patterns below are the shapes Masking searches. Each finds a name and its value; the rules
// decide what to hide.
public final class MaskingConstants {

  /** The mask character used when none is configured. */
  public static final String DEFAULT_MASK_CHAR = ".";

  // A value hidden whole shows at most this many mask characters, so a long one hides its length.
  static final int MAX_WHOLE_MASK = 10;

  // A masked body longer than this is cut.
  static final int MAX_LENGTH = 4_000;

  // <name>key</name><value>v</value>. Groups: opening, name, value, closing.
  static final Pattern XML_ITEM =
      Pattern.compile("(<name>\\s*([\\w:]+)\\s*</name>\\s*<value>)([^<]*)(</value>)");

  // <key>v</key>, <ns:key a="x">v</ns:key>. Groups: opening, name, value, closing.
  static final Pattern XML_ELEMENT =
      Pattern.compile("(<(?:[\\w-]+:)?([\\w-]+)(?:\\s[^>]*)?>)([^<]*)(</)");

  // key=v, key="v w". Groups: name, separator, quote, value. A quoted value runs to its closing
  // quote, spaces and commas included.
  static final Pattern KEY_EQUALS =
      Pattern.compile("(?<![\\w.-])([A-Za-z_][\\w.-]*)(=)(\"?)((?<=\")[^\"]*|[^\\s&,;\"']*)\\3");

  // key: v, "key":"v". A value followed by a colon is skipped, so 12:30:15 is not a pair.
  static final Pattern KEY_COLON =
      Pattern.compile(
          "(?<![\\w.-])([A-Za-z_][\\w.-]*)(\"?\\s*:\\s*)(\"?)((?<=\")[^\"]*+|[^\\s&,;\"':]*+)\\3(?!:)");

  // key v, in prose. Any two words match; only a configured name hides the next word.
  static final Pattern KEY_SPACE =
      Pattern.compile(
          "(?<![\\w.-])([A-Za-z_][\\w.-]*)(\\s+)(\"?)((?<=\")[^\"]+|[^\\s&,;\"':]+)\\3");

  // /key/v. Groups: name, value.
  static final Pattern KEY_PATH = Pattern.compile("/([A-Za-z_][\\w.-]*)/([^/?#\\s,;\"']+)");

  private MaskingConstants() {}
}
