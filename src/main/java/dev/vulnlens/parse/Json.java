package dev.vulnlens.parse;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal, zero-dependency JSON parser. Supports the full JSON grammar:
 * objects, arrays, strings (with escapes incl. backslash-u hex), numbers,
 * {@code true}/{@code false}/{@code null}. Duplicate object keys: last wins.
 */
public final class Json {

    private Json() {}

    public sealed interface Value permits JObject, JArray, JString, JNumber, JBool, JNull {
        default boolean isObject() { return this instanceof JObject; }
        default boolean isArray() { return this instanceof JArray; }
    }

    public record JObject(Map<String, Value> members) implements Value {
        public Value get(String key) { return members.get(key); }

        public JObject obj(String key) {
            Value v = members.get(key);
            return v instanceof JObject o ? o : null;
        }

        public JArray arr(String key) {
            Value v = members.get(key);
            return v instanceof JArray a ? a : null;
        }

        public String str(String key) {
            Value v = members.get(key);
            if (v instanceof JString s) return s.value();
            if (v instanceof JNumber n) return n.raw();
            return null;
        }

        public String str(String key, String def) {
            String s = str(key);
            return s != null ? s : def;
        }
    }

    public record JArray(List<Value> items) implements Value {
        public int size() { return items.size(); }
        public Value get(int i) { return items.get(i); }
    }

    public record JString(String value) implements Value {}
    public record JNumber(String raw) implements Value {
        public double asDouble() { return Double.parseDouble(raw); }
    }
    public record JBool(boolean value) implements Value {}
    public record JNull() implements Value {}

    public static final class ParseException extends RuntimeException {
        public ParseException(String message) { super(message); }
    }

    public static Value parse(String text) {
        Parser p = new Parser(text);
        Value v = p.parseValue();
        p.skipWs();
        if (!p.eof()) throw p.error("trailing characters after JSON value");
        return v;
    }

    private static final class Parser {
        private final String s;
        private int i;

        Parser(String s) { this.s = s; }

        ParseException error(String msg) {
            int from = Math.max(0, i - 12), to = Math.min(s.length(), i + 12);
            return new ParseException(msg + " at index " + i + " near ..." + s.substring(from, to) + "...");
        }

        boolean eof() { return i >= s.length(); }

        void skipWs() {
            while (!eof()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++;
                else break;
            }
        }

        char peek() {
            if (eof()) throw error("unexpected end of input");
            return s.charAt(i);
        }

        void expect(char c) {
            if (eof() || s.charAt(i) != c) throw error("expected '" + c + "'");
            i++;
        }

        Value parseValue() {
            skipWs();
            char c = peek();
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> new JString(parseString());
                case 't' -> parseLiteral("true", new JBool(true));
                case 'f' -> parseLiteral("false", new JBool(false));
                case 'n' -> parseLiteral("null", new JNull());
                default -> {
                    if (c == '-' || (c >= '0' && c <= '9')) yield parseNumber();
                    throw error("unexpected character '" + c + "'");
                }
            };
        }

        Value parseLiteral(String word, Value v) {
            if (s.startsWith(word, i)) { i += word.length(); return v; }
            throw error("invalid literal, expected " + word);
        }

        JObject parseObject() {
            expect('{');
            Map<String, Value> map = new LinkedHashMap<>();
            skipWs();
            if (peek() == '}') { i++; return new JObject(map); }
            while (true) {
                skipWs();
                if (peek() != '"') throw error("expected string key");
                String key = parseString();
                skipWs();
                expect(':');
                map.put(key, parseValue());
                skipWs();
                char c = peek();
                if (c == ',') { i++; continue; }
                if (c == '}') { i++; break; }
                throw error("expected ',' or '}'");
            }
            return new JObject(map);
        }

        JArray parseArray() {
            expect('[');
            List<Value> items = new ArrayList<>();
            skipWs();
            if (peek() == ']') { i++; return new JArray(items); }
            while (true) {
                items.add(parseValue());
                skipWs();
                char c = peek();
                if (c == ',') { i++; continue; }
                if (c == ']') { i++; break; }
                throw error("expected ',' or ']'");
            }
            return new JArray(items);
        }

        String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (eof()) throw error("unterminated string");
                char c = s.charAt(i++);
                if (c == '"') break;
                if (c == '\\') {
                    if (eof()) throw error("unterminated escape");
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (i + 4 > s.length()) throw error("bad unicode escape");
                            String hex = s.substring(i, i + 4);
                            try {
                                int cp = Integer.parseInt(hex, 16);
                                i += 4;
                                // handle surrogate pairs
                                if (Character.isHighSurrogate((char) cp) && i + 6 <= s.length()
                                        && s.charAt(i) == '\\' && s.charAt(i + 1) == 'u') {
                                    int lo = Integer.parseInt(s.substring(i + 2, i + 6), 16);
                                    if (Character.isLowSurrogate((char) lo)) {
                                        sb.appendCodePoint(Character.toCodePoint((char) cp, (char) lo));
                                        i += 6;
                                        break;
                                    }
                                }
                                sb.append((char) cp);
                            } catch (NumberFormatException ex) {
                                throw error("bad unicode escape \\u" + hex);
                            }
                        }
                        default -> throw error("invalid escape \\" + e);
                    }
                } else if (c < 0x20) {
                    throw error("unescaped control character in string");
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        JNumber parseNumber() {
            int start = i;
            if (!eof() && s.charAt(i) == '-') i++;
            if (eof()) throw error("bad number");
            if (s.charAt(i) == '0') {
                i++;
            } else if (s.charAt(i) >= '1' && s.charAt(i) <= '9') {
                while (!eof() && Character.isDigit(s.charAt(i))) i++;
            } else {
                throw error("bad number");
            }
            if (!eof() && s.charAt(i) == '.') {
                i++;
                if (eof() || !Character.isDigit(s.charAt(i))) throw error("bad number fraction");
                while (!eof() && Character.isDigit(s.charAt(i))) i++;
            }
            if (!eof() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                i++;
                if (!eof() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                if (eof() || !Character.isDigit(s.charAt(i))) throw error("bad number exponent");
                while (!eof() && Character.isDigit(s.charAt(i))) i++;
            }
            return new JNumber(s.substring(start, i));
        }
    }
}
