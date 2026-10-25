package dev.vulnlens.cli;

import dev.vulnlens.model.Severity;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * CLI argument parsing for VulnLens.
 */
public final class Args {

    public enum Format { HTML, JSON, TEXT }

    public record Config(
            String input,
            Format format,
            String output,       // null = default, "-" = stdout
            Severity failOn,     // null = disabled
            boolean noColor,
            boolean quiet,
            Duration timeout) {}

    public static Config parse(String[] args) {
        String input = null;
        Format format = Format.HTML;
        String output = null;
        Severity failOn = null;
        boolean noColor = false;
        boolean quiet = false;
        Duration timeout = Duration.ofSeconds(20);
        List<String> positionals = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--format" -> format = needEnum(args, ++i, "--format");
                case "--output" -> output = need(args, ++i, "--output");
                case "--fail-on" -> failOn = needSeverity(args, ++i);
                case "--no-color" -> noColor = true;
                case "--quiet" -> quiet = true;
                case "--timeout" -> timeout = Duration.ofSeconds(needInt(args, ++i, "--timeout"));
                case "--help", "-h" -> throw new UsageException(usage());
                case "--version", "-v" -> throw new UsageException("vulnlens 1.0.0");
                default -> {
                    if (a.startsWith("-")) throw new UsageException("unknown flag: " + a + "\n\n" + usage());
                    positionals.add(a);
                }
            }
        }
        if (positionals.size() != 1) {
            throw new UsageException(positionals.isEmpty()
                    ? "missing input: expected <pom.xml | project-dir>\n\n" + usage()
                    : "too many inputs: expected exactly one <pom.xml | project-dir>\n\n" + usage());
        }
        input = positionals.get(0);
        if (noColor || System.getenv("NO_COLOR") != null) noColor = true;
        return new Config(input, format, output, failOn, noColor, quiet, timeout);
    }

    private static String need(String[] args, int i, String flag) {
        if (i >= args.length) throw new UsageException(flag + " requires a value");
        return args[i];
    }

    private static Format needEnum(String[] args, int i, String flag) {
        String v = need(args, i, flag).toLowerCase();
        return switch (v) {
            case "html" -> Format.HTML;
            case "json" -> Format.JSON;
            case "text" -> Format.TEXT;
            default -> throw new UsageException("invalid --format: " + v + " (expected html|json|text)");
        };
    }

    private static Severity needSeverity(String[] args, int i) {
        String v = need(args, i, "--fail-on").toLowerCase();
        return switch (v) {
            case "critical", "high", "medium", "low" -> Severity.ofLevel(v);
            default -> throw new UsageException("invalid --fail-on: " + v + " (expected critical|high|medium|low)");
        };
    }

    private static int needInt(String[] args, int i, String flag) {
        try {
            int v = Integer.parseInt(need(args, i, flag));
            if (v < 5 || v > 300) throw new UsageException(flag + " must be between 5 and 300 seconds");
            return v;
        } catch (NumberFormatException e) {
            throw new UsageException(flag + " must be a number of seconds");
        }
    }

    public static String defaultOutput(Format format) {
        return switch (format) {
            case HTML -> "vulnlens-report.html";
            case JSON -> "vulnlens-report.json";
            case TEXT -> "vulnlens-report.txt";
        };
    }

    public static String usage() {
        return """
                Usage: vulnlens <pom.xml | project-dir> [options]

                X-ray a Maven project's supply chain against the live OSV.dev database.

                Options:
                  --format html|json|text   report format (default: html)
                  --output <path>           write report here ("-" for stdout);
                                            default: vulnlens-report.<ext> in cwd
                  --fail-on <level>         exit 1 if any finding is at/above level
                                            (critical|high|medium|low) — for CI
                  --timeout <seconds>       per-request timeout, 5–300 (default: 20)
                  --no-color                disable ANSI colors (also: NO_COLOR env)
                  --quiet                   only print the output path / report
                  --help, -h                show this help
                  --version, -v             show version

                Exit codes: 0 ok · 1 --fail-on threshold hit · 2 bad input · 3 OSV.dev unreachable""";
    }

    public static final class UsageException extends RuntimeException {
        public UsageException(String message) { super(message); }
    }
}
