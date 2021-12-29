package com.logpresso.scanner;

import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.SystemOutRule;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @see <a href="https://archive.apache.org/dist/logging/log4j/">Log4j2
 *      downloads</a>
 */
public class Log4jScannerTest {

	@Rule
	public final SystemOutRule systemOutRule = new SystemOutRule().enableLog();

	@Test
	public void scanVariousVersions_log4j2() throws Exception {
		Log4j2Scanner scanner = new Log4j2Scanner();
		int returnCode = scanner.run(new String[] { getTestFiles("log4j2") });

		assertEquals(1, returnCode);
		String log = systemOutRule.getLog();
		assertTrue(log.contains("Scanned 1 directories and 10 files"));
		assertTrue(log.contains("Found 9 vulnerable files"));
		assertTrue(log.contains("Found 1 potentially vulnerable files"));
		assertTrue(log.contains("Found 0 mitigated files"));

		Pattern pattern;
		pattern = getPattern_log4j2("CVE-2021-44228", "log4j-core.2.12.1.jar", "2.12.1", false);
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j2("CVE-2021-45046", "outerlog4j.jar (innerlog4j.jar > log4j-core.2.15.0.jar)", "2.15.0", false);
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j2("CVE-2021-45046", "log4j-core.2.15.0.jar", "2.15.0", false);
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j2("CVE-2021-44228", "loggingBuddies.war (log4j-core-2.12.1.jar)", "2.12.1", false);
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j2("CVE-2021-44228", "loggingBuddies.war (log4j-core.2.14.0.jar)", "2.14.0", false);
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j2("CVE-2021-45046", "loggingBuddies.war (log4j-core.2.15.0.jar)", "2.15.0", false);
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j2("CVE-2021-45105", "loggingBuddies.war (log4j-core.2.16.0.jar)", "2.16.0", false);
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j2("CVE-2021-44228", "log4j-core-2.15.0_potentially.jar", "N/A", true);
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j2("CVE-2021-44228", "log4j-core.2.14.0.jar", "2.14.0", false);
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j2("CVE-2021-45105", "log4j-core.2.16.0.jar", "2.16.0", false);
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j2("CVE-2021-44832", "log4j-core.2.17.0.jar", "2.17.0", false);
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j2("CVE-2021-44832", "log4j-core.2.12.3.jar", "2.12.3", false);
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j2("CVE-2021-44832", "log4j-core.2.3.1.jar", "2.3.1", false);
		assertTrue(pattern.matcher(log).find());
	}

	@Test
	public void scanSafeVersion_log4j2() throws Exception {
		Log4j2Scanner scanner = new Log4j2Scanner();
		int returnCode = scanner.run(new String[] { getTestFiles("log4j2-ok") });
		assertEquals(0, returnCode);
		String log = systemOutRule.getLog();
		assertTrue(log.contains("Scanned 1 directories and 1 files"));
		assertTrue(log.contains("Found 0 vulnerable files"));
		assertTrue(log.contains("Found 0 potentially vulnerable files"));
		assertTrue(log.contains("Found 0 mitigated files"));
	}

	@Test
	public void scanVariousVersions_log4j1() throws Exception {
		Log4j2Scanner scanner = new Log4j2Scanner();
		int returnCode = scanner.run(new String[] { "--scan-log4j1", getTestFiles("log4j1") });

		assertEquals(1, returnCode);
		String log = systemOutRule.getLog();
		assertTrue(log.contains("Scanned 1 directories and 4 files"));
		assertTrue(log.contains("Found 0 vulnerable files"));
		assertTrue(log.contains("Found 4 potentially vulnerable files"));
		assertTrue(log.contains("Found 0 mitigated files"));

		Pattern pattern;
		pattern = getPattern_log4j1("log4j-1.2.17.jar", "1.2.17");
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j1("log4j-1.2.17_potentially.jar", "N/A");
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j1("log4j1_buddies_outer.aar (log4j1_buddies.ear > log4j-1.2.17_potentially.jar)", "N/A");
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j1("log4j1_buddies_outer.aar (log4j1_buddies.ear > log4j-1.2.17.jar)", "1.2.17");
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j1("log4j1_buddies.ear (log4j-1.2.17_potentially.jar)", "N/A");
		assertTrue(pattern.matcher(log).find());
		pattern = getPattern_log4j1("log4j1_buddies.ear (log4j-1.2.17.jar)", "1.2.17");
		assertTrue(pattern.matcher(log).find());
	}

	private String getTestFiles(String dir) {
		Path resourceDirectory = Paths.get("src", "test", "resources", dir);
		return resourceDirectory.toFile().getAbsolutePath();
	}

	private Pattern getPattern_log4j2(String cve, String jar, String version, boolean pot) {
		String v = version.replaceAll("\\.", "\\\\.");
		String j = jar.replaceAll("\\.", "\\\\.");
		j = j.replaceAll("\\(", "\\\\(");
		j = j.replaceAll("\\)", "\\\\)");

		String prefix = pot ? "\\[\\?\\]" : "\\[\\*\\]";

		return Pattern
				.compile("(" + prefix + " Found " + cve + " \\(log4j 2\\.x\\) vulnerability in)(.*)(" + j + ", log4j " + v + ")");
	}

	private Pattern getPattern_log4j1(String jar, String version) {
		String v = version.replaceAll("\\.", "\\\\.");
		String j = jar.replaceAll("\\.", "\\\\.");
		j = j.replaceAll("\\(", "\\\\(");
		j = j.replaceAll("\\)", "\\\\)");

		return Pattern
				.compile("(\\[\\?\\] Found CVE-2021-4104  \\(log4j 1\\.2\\) vulnerability in)(.*)(" + j + ", log4j " + v + ")");
	}
}
