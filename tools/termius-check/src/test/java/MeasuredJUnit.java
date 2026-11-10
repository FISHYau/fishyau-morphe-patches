import com.google.gson.GsonBuilder;
import org.junit.internal.TextListener;
import org.junit.runner.Description;
import org.junit.runner.JUnitCore;
import org.junit.runner.Request;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunListener;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Source-test measurements only. No final-MPP loading or parser-class evidence. */
public final class MeasuredJUnit extends RunListener {
    private final List<Map<String, Object>> cases = new ArrayList<>();
    private final Map<Description, Map<String, Object>> active = new LinkedHashMap<>();
    private final Map<Description, Long> starts = new LinkedHashMap<>();
    private final List<Map<String, Object>> unscopedFailures = new ArrayList<>();

    private static Map<String, Object> identity(Description d) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("class_name", d.getClassName());
        row.put("method_name", d.getMethodName());
        row.put("display_name", d.getDisplayName());
        return row;
    }
    private static void leaves(Description d, List<Map<String, Object>> rows) {
        if (d.isTest()) rows.add(identity(d));
        else for (Description child : d.getChildren()) leaves(child, rows);
    }
    private Map<String, Object> start(Description d) {
        if (active.containsKey(d)) throw new IllegalStateException("Duplicate active test: " + d);
        Map<String, Object> row = identity(d);
        row.put("started_at", Instant.now().toString());
        row.put("outcome", "passed");
        row.put("failures", new ArrayList<Map<String, Object>>());
        row.put("assumptions", new ArrayList<Map<String, Object>>());
        cases.add(row);
        active.put(d, row);
        starts.put(d, System.nanoTime());
        return row;
    }
    @Override public void testStarted(Description d) { start(d); }
    @Override public void testFinished(Description d) {
        Map<String, Object> row = active.remove(d);
        if (row == null) throw new IllegalStateException("Finish without start: " + d);
        row.put("ended_at", Instant.now().toString());
        row.put("duration_ns", System.nanoTime() - starts.remove(d));
    }
    private static Map<String, Object> failure(Failure f) {
        Map<String, Object> row = identity(f.getDescription());
        row.put("exception_class", f.getException().getClass().getName());
        row.put("message", f.getMessage());
        row.put("trace", f.getTrace());
        return row;
    }
    @SuppressWarnings("unchecked")
    private void record(Failure f, String field, String outcome) {
        Map<String, Object> row = active.get(f.getDescription());
        if (row == null) unscopedFailures.add(failure(f));
        else {
            ((List<Map<String, Object>>) row.get(field)).add(failure(f));
            // A subsequent assumption cannot erase a prior failure.
            if (!"failed".equals(row.get("outcome"))) row.put("outcome", outcome);
        }
    }
    @Override public void testFailure(Failure f) { record(f, "failures", "failed"); }
    @Override public void testAssumptionFailure(Failure f) { record(f, "assumptions", "assumption_failed"); }
    @Override public void testIgnored(Description d) {
        start(d).put("outcome", "ignored");
        testFinished(d);
    }
    public static void main(String[] args) throws Exception {
        if (args.length < 2) throw new IllegalArgumentException("NEW report path and explicit test classes required");
        Path output = Path.of(args[0]);
        if (Files.exists(output)) throw new IllegalArgumentException("Report must be new");
        MeasuredJUnit listener = new MeasuredJUnit();
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("schema", "source-junit-measurements-v1");
        report.put("status", "failed");
        report.put("requested_classes", Arrays.asList(args).subList(1, args.length));
        report.put("started_at", Instant.now().toString());
        long start = System.nanoTime();
        report.put("cases", listener.cases);
        report.put("unscoped_failures", listener.unscopedFailures);
        boolean success = false;
        try {
            Class<?>[] classes = new Class<?>[args.length - 1];
            for (int i = 1; i < args.length; i++) classes[i - 1] = Class.forName(args[i]);
            org.junit.runner.Runner runner = Request.classes(classes).getRunner();
            List<Map<String, Object>> planned = new ArrayList<>();
            leaves(runner.getDescription(), planned);
            report.put("planned_cases", planned);
            JUnitCore core = new JUnitCore();
            core.addListener(new TextListener(System.out)); // Retain JUnit log/OK summary compatibility.
            core.addListener(listener);
            Result result = core.run(runner);
            Map<String, Object> totals = new LinkedHashMap<>();
            totals.put("run_count", result.getRunCount());
            totals.put("failure_count", result.getFailureCount());
            totals.put("ignore_count", result.getIgnoreCount());
            totals.put("assumption_failure_count", result.getAssumptionFailureCount());
            report.put("totals", totals);
            success = result.wasSuccessful() && result.getRunCount() > 0 && result.getIgnoreCount() == 0
                && result.getAssumptionFailureCount() == 0 && listener.active.isEmpty()
                && listener.unscopedFailures.isEmpty() && planned.size() == listener.cases.size()
                && listener.cases.stream().allMatch(c -> "passed".equals(c.get("outcome")));
            if (success) report.put("status", "source_tests_passed");
        } catch (Throwable failure) {
            report.put("error", failure.toString());
            throw failure;
        } finally {
            report.put("ended_at", Instant.now().toString());
            report.put("duration_ns", System.nanoTime() - start);
            report.put("incomplete_count", listener.active.size());
            Files.writeString(output, new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(report) + "\n",
                StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
        }
        if (!success) System.exit(1);
    }
}
