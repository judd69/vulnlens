package dev.vulnlens.util;

/**
 * Minimal ANSI color helper. Emits nothing when disabled.
 */
public final class Ansi {
    private final boolean on;

    public Ansi(boolean on) { this.on = on; }

    private String code(String c) { return on ? c : ""; }

    public String reset() { return code("\u001B[0m"); }
    public String bold(String s) { return code("\u001B[1m") + s + code("\u001B[0m"); }
    public String red() { return code("\u001B[31m"); }
    public String yellow() { return code("\u001B[33m"); }
    public String green() { return code("\u001B[32m"); }
    public String cyan() { return code("\u001B[36m"); }
    public String dim(String s) { return code("\u001B[2m") + s + code("\u001B[0m"); }
}
