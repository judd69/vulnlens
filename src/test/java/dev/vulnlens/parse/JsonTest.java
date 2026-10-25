package dev.vulnlens.parse;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JsonTest {

    @Test
    void parsesSimpleObject() {
        Json.JObject o = (Json.JObject) Json.parse("{\"a\":1,\"b\":\"x\",\"c\":true,\"d\":null}");
        assertEquals("1", ((Json.JNumber) o.get("a")).raw());
        assertEquals("x", o.str("b"));
        assertTrue(((Json.JBool) o.get("c")).value());
        assertInstanceOf(Json.JNull.class, o.get("d"));
    }

    @Test
    void parsesNestedStructures() {
        Json.JObject o = (Json.JObject) Json.parse("{\"arr\":[1,{\"k\":[true,false]},\"s\"],\"n\":-2.5e3}");
        Json.JArray arr = o.arr("arr");
        assertEquals(3, arr.size());
        assertEquals("s", ((Json.JString) arr.get(2)).value());
        assertEquals(-2500.0, ((Json.JNumber) o.get("n")).asDouble());
    }

    @Test
    void parsesStringEscapes() {
        Json.JString s = (Json.JString) Json.parse("\"a\\\"b\\\\c\\nd\\u0041\\u00e9\"");
        assertEquals("a\"b\\c\ndAé", s.value());
    }

    @Test
    void parsesSurrogatePair() {
        Json.JString s = (Json.JString) Json.parse("\"\\uD83D\\uDE00\"");
        assertEquals("\uD83D\uDE00", s.value());
    }

    @Test
    void parsesNumbers() {
        assertEquals("42", ((Json.JNumber) Json.parse("42")).raw());
        assertEquals("-0.5", ((Json.JNumber) Json.parse("-0.5")).raw());
        assertEquals("1e10", ((Json.JNumber) Json.parse("1e10")).raw());
        assertEquals("3E-2", ((Json.JNumber) Json.parse("3E-2")).raw());
    }

    @Test
    void parsesEmptyContainers() {
        assertTrue(((Json.JObject) Json.parse("{}")).members().isEmpty());
        assertTrue(((Json.JArray) Json.parse("[]")).items().isEmpty());
        assertTrue(((Json.JArray) Json.parse(" [ ] ")).items().isEmpty());
    }

    @Test
    void duplicateKeysLastWins() {
        Json.JObject o = (Json.JObject) Json.parse("{\"a\":1,\"a\":2}");
        assertEquals("2", ((Json.JNumber) o.get("a")).raw());
    }

    @Test
    void rejectsTrailingComma() {
        assertThrows(Json.ParseException.class, () -> Json.parse("{\"a\":1,}"));
        assertThrows(Json.ParseException.class, () -> Json.parse("[1,2,]"));
    }

    @Test
    void rejectsUnterminatedString() {
        assertThrows(Json.ParseException.class, () -> Json.parse("\"abc"));
    }

    @Test
    void rejectsBadEscape() {
        assertThrows(Json.ParseException.class, () -> Json.parse("\"a\\qb\""));
    }

    @Test
    void rejectsTrailingGarbage() {
        assertThrows(Json.ParseException.class, () -> Json.parse("{} {}"));
    }

    @Test
    void rejectsBadNumber() {
        assertThrows(Json.ParseException.class, () -> Json.parse("01"));
        assertThrows(Json.ParseException.class, () -> Json.parse("1."));
    }

    @Test
    void parsesOsvShapedPayload() {
        String payload = "{\"results\":[{\"vulns\":[{\"id\":\"CVE-2021-44228\",\"severity\":[{\"type\":\"CVSS_V3\",\"score\":\"10.0\"}]}]},{}]}";
        Json.JObject o = (Json.JObject) Json.parse(payload);
        Json.JArray results = o.arr("results");
        assertEquals(2, results.size());
        Json.JObject first = (Json.JObject) results.get(0);
        assertEquals("CVE-2021-44228", first.arr("vulns").get(0) instanceof Json.JObject v ? v.str("id") : null);
    }
}
