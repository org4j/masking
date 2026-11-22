package io.github.org4j.masking;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

// The specification of Masking: what each rule hides, and where.
class MaskingTest {

  private static final String JSON = "application/json";
  private static final String FORM = "application/x-www-form-urlencoded";
  private static final Pattern LONG_NUMBER = Pattern.compile("(?<!\\d)\\d{13,19}(?!\\d)");

  private static Masking masking(Set<String> fields, Set<String> fullFields, Pattern... values) {
    return new Masking(new MaskingRules(".", fields, fullFields, List.of(values)));
  }

  private static String body(Masking masking, String body, String contentType) {
    return masking.body(body.getBytes(StandardCharsets.UTF_8), contentType);
  }

  @Nested
  class WithNothingConfigured {

    private final Masking masking = Masking.empty();

    @Test
    void isDisabled() {
      assertThat(masking.isEnabled()).isFalse();
      assertThat(Masking.defaults().isEnabled()).isFalse();
    }

    @Test
    void leavesEveryTextAsItIs() {
      var json = "{\"pan\":\"8600301234567890\",\"cvv\":\"123\",\"password\":\"s3cr3t\"}";
      assertThat(body(masking, json, JSON)).isEqualTo(json);

      var text = "failed: pan=8600301234567890 cvv=123 password=s3cr3t at 12:30";
      assertThat(masking.text(text)).isEqualTo(text);

      var uri = URI.create("http://api.local/pay?pan=8600301234567890&cvv=123");
      assertThat(masking.uri(uri)).isEqualTo(uri.toString());
    }
  }

  @Nested
  class TheBaseHookForFields {

    private final Masking masking = new Masking(MaskingRules.of(List.of("pan", "cvv", "pin")));

    @Test
    void keepsTheFirst6AndLast4CharactersOfALongValue() {
      assertThat(masking.mask("pan", "8600301234567890")).isEqualTo("860030......7890");
      assertThat(masking.maskValue("8600301234567890")).isEqualTo("860030......7890");
    }

    @Test
    void hidesAValueShorterThan10CharactersWhole() {
      assertThat(masking.mask("cvv", "123")).isEqualTo("...");
      assertThat(masking.mask("pin", "123456789")).isEqualTo(".........");
    }

    @Test
    void leavesUnconfiguredNamesAlone() {
      var json = "{\"pan\":\"8600301234567890\",\"orderId\":9876543210123456}";
      assertThat(body(masking, json, JSON))
          .isEqualTo("{\"pan\":\"860030......7890\",\"orderId\":9876543210123456}");
    }

    @Test
    void comparesNamesIgnoringCaseAndByTheirLastPart() {
      assertThat(masking.contains("PAN")).isTrue();
      assertThat(masking.text("card.pan:8600301234567890 order.cvv:123"))
          .isEqualTo("card.pan:860030......7890 order.cvv:...");
    }

    @Test
    void usesTheConfiguredMaskCharacter() {
      var stars = new Masking(MaskingRules.of("*", List.of("pan", "cvv")));
      assertThat(stars.maskValue("8600301234567890")).isEqualTo("860030******7890");
      assertThat(stars.maskValue("123")).isEqualTo("***");
    }
  }

  @Nested
  class FullFields {

    private final Masking masking = masking(Set.of("pan"), Set.of("client_secret", "fullname"));

    @Test
    void hideAShortValueCharacterForCharacter() {
      assertThat(masking.mask("client_secret", "s3cr3t")).isEqualTo("......");
    }

    @Test
    void hideALongValueBehind10MaskCharactersWhateverItsLength() {
      assertThat(masking.mask("client_secret", "0123456789abcdef")).isEqualTo("..........");
      assertThat(masking.mask("fullname", "AZIZ KARIMOV")).isEqualTo("..........");
    }

    @Test
    void winOverTheBaseHookWhenANameIsInBothLists() {
      var both = masking(Set.of("secret"), Set.of("secret"));
      assertThat(both.mask("secret", "0123456789abcdef")).isEqualTo("..........");
    }

    @Test
    void areFoundInEveryFormat() {
      assertThat(
              body(
                  masking,
                  "{\"pan\":\"8600301234567890\",\"client_secret\":\"0123456789abcdef\"}",
                  JSON))
          .isEqualTo("{\"pan\":\"860030......7890\",\"client_secret\":\"..........\"}");
      assertThat(body(masking, "<Card><fullname>AZIZ KARIMOV</fullname></Card>", "text/xml"))
          .isEqualTo("<Card><fullname>..........</fullname></Card>");
      assertThat(body(masking, "client_secret=0123456789abcdef&pan=8600301234567890", FORM))
          .isEqualTo("client_secret=..........&pan=860030......7890");
      assertThat(masking.text("token refused, client_secret=0123456789abcdef"))
          .isEqualTo("token refused, client_secret=..........");
      assertThat(masking.uri(URI.create("https://idp.local/client_secret/0123456789abcdef")))
          .isEqualTo("https://idp.local/client_secret/..........");
    }
  }

  @Nested
  class ValuePatterns {

    private final Masking masking = masking(Set.of(), Set.of(), LONG_NUMBER);

    @Test
    void enableMaskingOnTheirOwn() {
      assertThat(masking.isEnabled()).isTrue();
    }

    @Test
    void findAValueWithNoNameAroundItAndTakeTheBaseHook() {
      assertThat(masking.text("declined: 8600301234567890 at 12:30, order 42"))
          .isEqualTo("declined: 860030......7890 at 12:30, order 42");
    }

    @Test
    void searchBodiesAndUrisToo() {
      assertThat(body(masking, "{\"message\":\"card 9860090101191238 declined\"}", JSON))
          .isEqualTo("{\"message\":\"card 986009......1238 declined\"}");
      assertThat(masking.uri(URI.create("https://api.local/v1/cards/8600301234567890?ref=42")))
          .isEqualTo("https://api.local/v1/cards/860030......7890?ref=42");
    }

    @Test
    void doNotFindAValueAFullFieldAlreadyHid() {
      var both = masking(Set.of(), Set.of("secret"), LONG_NUMBER);
      assertThat(both.text("secret=8600301234567890")).isEqualTo("secret=..........");
    }

    @Test
    void findNothingWhenNoneIsConfigured() {
      var namesOnly = new Masking(MaskingRules.of(List.of("pan")));
      assertThat(namesOnly.text("declined: 8600301234567890"))
          .isEqualTo("declined: 8600301234567890");
    }
  }

  @Nested
  class Formats {

    private final Masking masking =
        new Masking(MaskingRules.of(List.of("pan", "client_secret", "card")));

    @Test
    void jsonAtAnyDepthAndInArrays() {
      var json = "{\"payer\":{\"cards\":[{\"pan\":\"8600301234567890\"}]},\"pan\":null}";
      assertThat(body(masking, json, "application/problem+json;charset=UTF-8"))
          .isEqualTo("{\"payer\":{\"cards\":[{\"pan\":\"860030......7890\"}]},\"pan\":null}");
    }

    @Test
    void jsonThatDoesNotParseIsNotShown() {
      var cut = "{\"pan\":\"8600301234567890\"";
      assertThat(body(masking, cut, JSON)).isEqualTo("<" + cut.length() + " characters, not JSON>");
    }

    @Test
    void xmlElementsAndNameValueItems() {
      assertThat(body(masking, "<ns:pan id=\"1\">8600301234567890</ns:pan>", "application/xml"))
          .isEqualTo("<ns:pan id=\"1\">860030......7890</ns:pan>");
      var items = "<item><name>pan</name><value>9860090101191238</value></item>";
      assertThat(body(masking, items, "text/xml"))
          .isEqualTo("<item><name>pan</name><value>986009......1238</value></item>");
    }

    @Test
    void formsAndUriQueries() {
      assertThat(body(masking, "client_id=partner&client_secret=s3cr3t", FORM))
          .isEqualTo("client_id=partner&client_secret=......");
      assertThat(masking.uri(URI.create("https://api.local/checkout?pan=8600301234567890&ref=123")))
          .isEqualTo("https://api.local/checkout?pan=860030......7890&ref=123");
    }

    @Test
    void plainTextPairs() {
      var text = "pan=8600301234567890 client_secret: topsecret paid with card 8600301234567890";
      assertThat(masking.text(text))
          .isEqualTo(
              "pan=860030......7890 client_secret: ......... paid with card 860030......7890");
    }

    @Test
    void quotedValuesWholeEvenWithSpacesOrCommas() {
      assertThat(masking.text("client_secret=\"my s3cr3t\" ok"))
          .isEqualTo("client_secret=\".........\" ok");
      assertThat(masking.text("{\"client_secret\":\"a,b c\",\"x\":1}"))
          .isEqualTo("{\"client_secret\":\".....\",\"x\":1}");
      assertThat(masking.text("client_secret \"two words\""))
          .isEqualTo("client_secret \".........\"");
      assertThat(masking.text("pan=\"8600 3012 3456 7890\""))
          .isEqualTo("pan=\"8600 3.........7890\"");
    }

    @Test
    void timesAreNotReadAsPairs() {
      assertThat(masking.text("card: 12:30:15")).isEqualTo("card: 12:30:15");
    }

    @Test
    void pathSegmentsWhereverTheyStand() {
      assertThat(masking.uri(URI.create("https://api.local/cards/pan/8600301234567890")))
          .isEqualTo("https://api.local/cards/pan/860030......7890");
      assertThat(masking.uri(URI.create("https://api.local/v1/cards/pan/8600301234567890?x=1")))
          .isEqualTo("https://api.local/v1/cards/pan/860030......7890?x=1");
    }

    @Test
    void otherContentTypesShowOnlyTheirSize() {
      assertThat(body(masking, "pan=8600301234567890", "text/plain"))
          .isEqualTo("<20 bytes, text/plain>");
      assertThat(masking.body(new byte[] {1, 2, 3}, null)).isEqualTo("<3 bytes>");
    }

    @Test
    void anEmptyBodyIsEmpty() {
      assertThat(masking.body(null, JSON)).isEmpty();
      assertThat(masking.body(new byte[0], JSON)).isEmpty();
    }

    @Test
    void aLongBodyIsCutAfterMasking() {
      var json = "{\"pan\":\"8600301234567890\",\"note\":\"" + "x".repeat(5_000) + "\"}";
      assertThat(body(masking, json, JSON))
          .startsWith("{\"pan\":\"860030......7890\"")
          .hasSize(MaskingConstants.MAX_LENGTH + 1)
          .endsWith("…");
    }
  }
}
