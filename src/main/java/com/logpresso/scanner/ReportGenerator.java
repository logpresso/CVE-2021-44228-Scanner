package com.logpresso.scanner;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.logpresso.scanner.json.JsonArray;
import com.logpresso.scanner.json.JsonObject;
import com.logpresso.scanner.utils.FileUtils;
import com.logpresso.scanner.utils.IoUtils;

public class ReportGenerator {

	public static void checkApiKey(Configuration config) {
		HttpURLConnection conn = null;
		try {
			conn = newConnection(config);
			conn.setRequestMethod("HEAD");
			int status = conn.getResponseCode();
			if (status == 401)
				throw new IllegalArgumentException("Invalid API key " + config.getApiKey());

			if (status == 402)
				throw new IllegalArgumentException("Check host quota for logpresso.watch");
			
			if (status == 403)
				throw new IllegalArgumentException("Host is already registered to other organization. Delete log4j2-scan.guid file to reset.");

			if (status != 200)
				throw new IllegalArgumentException("Unknown http error " + status);

		} catch (IOException e) {
			throw new IllegalArgumentException("Check logpresso.watch connectivity (" + e.getMessage() + ")");
		} finally {
			if (conn != null)
				conn.disconnect();
		}
	}

	public static void sendReport(Configuration config, Metrics metrics, Detector detector) {
		if (config.getApiKey() == null)
			return;

		HttpURLConnection conn = null;
		try {
			conn = newConnection(config);
			conn.setDoOutput(true);
			conn.setRequestMethod("POST");

			writeJsonReport(config, detector, conn.getOutputStream(), metrics);

			int status = conn.getResponseCode();
			if (status == 200) {
				System.out.println("[*] Sent report to Logpresso Watch successfully.");
			} else {
				BufferedReader br = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "UTF-8"));
				String line = br.readLine();
				Pattern p = Pattern.compile("\\{\"msg\":\"([^\"]+)\"\\}");
				Matcher matcher = p.matcher(line);
				if (matcher.find()) {
					System.out.println("Error: Cannot send report to Logpresso Watch (" + matcher.group(1) + ")");
				}
			}

		} catch (IOException e) {
			throw new IllegalStateException(e);
		} finally {
			if (conn != null)
				conn.disconnect();
		}
	}

	private static HttpURLConnection newConnection(Configuration config) throws IOException, MalformedURLException {
		HttpURLConnection conn;
		UUID hostGuid = ensureHostGuid();
		conn = (HttpURLConnection) new URL("https://logpresso.watch/logs/log4j/" + hostGuid).openConnection();
		conn.setConnectTimeout(30000);
		conn.setReadTimeout(30000);
		conn.setRequestProperty("Authorization", "Bearer " + config.getApiKey());
		conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");

		return conn;
	}

	private static UUID ensureHostGuid() {
		File dir = IoUtils.getJarDir();
		File guidFile = new File(dir, "log4j2-scan.guid");
		if (guidFile.exists()) {
			try {
				return UUID.fromString(FileUtils.readLine(guidFile));
			} catch (IOException e) {
				throw new IllegalStateException("Cannot read log4j2-scan.guid file", e);
			}
		} else {
			try {
				UUID newGuid = UUID.randomUUID();
				FileUtils.writeLine(guidFile, newGuid.toString());
				return newGuid;
			} catch (IOException e) {
				throw new IllegalStateException("Cannot write log4j2-scan.guid file", e);
			}
		}
	}

	public static void writeReportFile(Configuration config, Metrics metrics, Detector detector) {
		Map<File, List<ReportEntry>> fileReports = detector.getFileReports();

		if (!config.isReportCsv() && !config.isReportJson())
			return;

		if (config.isNoEmptyReport() && fileReports.isEmpty())
			return;

		if (config.isReportCsv()) {
			File f = generateReportFileName(config, metrics, ".csv");
			FileOutputStream fos = null;
			try {
				fos = new FileOutputStream(f);
				writeCsvReport(config, fileReports, fos);
			} catch (IOException e) {
				throw new IllegalStateException("cannot open csv report file: " + e.getMessage(), e);
			} finally {
				IoUtils.ensureClose(fos);
			}
		}

		if (config.isReportJson()) {
			File f = generateReportFileName(config, metrics, ".json");
			FileOutputStream fos = null;
			try {
				fos = new FileOutputStream(f);
				writeJsonReport(config, detector, fos, metrics);
			} catch (IOException e) {
				throw new IllegalStateException("cannot open json report file: " + e.getMessage(), e);
			} finally {
				IoUtils.ensureClose(fos);
			}
		}
	}

	private static File generateReportFileName(Configuration config, Metrics metrics, String ext) {
		SimpleDateFormat df = new SimpleDateFormat("yyyyMMdd_HHmmss");

		File f = new File("log4j2_scan_report_" + df.format(new Date(metrics.getScanStartTime())) + ext);
		if (config.getReportPath() != null) {
			f = new File(config.getReportPath());

			// double check
			if (f.exists())
				throw new IllegalStateException("Cannot write report file. File already exists: " + f.getAbsolutePath());
		} else if (config.getReportDir() != null) {
			f = new File(config.getReportDir(), f.getName());

			// double check
			if (f.exists())
				throw new IllegalStateException("Cannot write report file. File already exists: " + f.getAbsolutePath());
		}

		return f;
	}

	private static void writeCsvReport(Configuration config, Map<File, List<ReportEntry>> fileReports, OutputStream csvStream)
			throws IOException, UnsupportedEncodingException {
		String header = String
				.format("\"Hostname\",\"Path\",\"Entry\",\"Product\",\"Version\",\"CVE\",\"Status\",\"Fixed\",\"Detected at\"%n");
		csvStream.write(header.getBytes("utf-8"));

		String hostname = IoUtils.getHostname(config.isDebug());
		if (hostname == null)
			hostname = "";

		for (File file : fileReports.keySet()) {
			for (ReportEntry entry : fileReports.get(file)) {
				String line = entry.getCsvLine(hostname);
				csvStream.write(line.getBytes("utf-8"));
			}
		}
	}

	private static void writeJsonReport(Configuration config, Detector detector, OutputStream outputStream, Metrics metrics)
			throws IOException {

		// elapsed time in seconds
		long elapsedTime = (System.currentTimeMillis() - metrics.getScanStartTime()) / 1000;

		JsonObject root = new JsonObject();
		JsonArray files = new JsonArray();
		JsonArray errors = null;

		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");

		Map<File, List<ReportEntry>> fileReports = detector.getFileReports();
		for (File file : fileReports.keySet()) {
			JsonArray reports = new JsonArray();

			boolean vulnerable = false;
			boolean potentiallyVulnerable = false;
			boolean mitigated = false;
			for (ReportEntry entry : fileReports.get(file)) {
				vulnerable |= (entry.getStatus() == Status.VULNERABLE);
				potentiallyVulnerable |= (entry.getStatus() == Status.POTENTIALLY_VULNERABLE);
				mitigated |= (entry.getStatus() == Status.MITIGATED);

				JsonObject report = new JsonObject();
				report.put("entry", entry.getEntry());
				report.put("product", entry.getProduct());
				report.put("version", entry.getVersion());
				report.put("cve", entry.getCve());
				report.put("status", entry.getStatus().toString());
				report.put("fixed", entry.isFixed());
				report.put("detected_at", df.format(entry.getReportTime()));
				reports.add(report);
			}

			Status status = Status.NOT_VULNERABLE;
			if (vulnerable)
				status = Status.VULNERABLE;
			else if (potentiallyVulnerable)
				status = Status.POTENTIALLY_VULNERABLE;
			else if (mitigated)
				status = Status.MITIGATED;

			JsonObject fileObj = new JsonObject();
			fileObj.put("path", file.getAbsolutePath());
			fileObj.put("status", status.toString());
			fileObj.put("reports", reports);

			files.add(fileObj);
		}

		if (!detector.getErrorReports().isEmpty()) {
			errors = new JsonArray();
			for (ReportEntry entry : detector.getErrorReports()) {
				JsonObject error = new JsonObject();
				error.put("path", entry.getPath().getAbsolutePath());
				error.put("error", entry.getError());
				error.put("created_at", df.format(entry.getReportTime()));
				errors.add(error);
			}
		}

		String hostname = IoUtils.getHostname(config.isDebug());

		JsonArray argArray = new JsonArray();
		for (String arg : config.getArgs())
			argArray.add(arg);

		JsonObject summary = new JsonObject();
		summary.put("scanner_banner", Log4j2Scanner.BANNER);
		summary.put("scanner_version", Log4j2Scanner.VERSION);
		summary.put("scanner_release_date", Log4j2Scanner.RELEASE_DATE);
		summary.put("scanner_args", argArray);
		summary.put("os_name", System.getProperty("os.name"));
		summary.put("hostname", hostname);
		summary.put("user", System.getProperty("user.name"));
		summary.put("elapsed_time", elapsedTime);
		summary.put("scan_start_time", df.format(new Date(metrics.getScanStartTime())));
		summary.put("scan_end_time", df.format(new Date()));
		summary.put("scan_dir_count", metrics.getScanDirCount());
		summary.put("scan_file_count", metrics.getScanFileCount());
		summary.put("vulnerable_file_count", detector.getVulnerableFileCount());
		summary.put("potentially_vulnerable_file_count", detector.getPotentiallyVulnerableFileCount());
		summary.put("mitigated_file_count", detector.getMitigatedFileCount());
		summary.put("fixed_file_count", metrics.getFixedFileCount());
		summary.put("error_file_count", metrics.getErrorCount() + detector.getErrorCount());

		root.put("summary", summary);

		if (!fileReports.isEmpty())
			root.put("files", files);

		if (errors != null)
			root.put("errors", errors);

		Writer writer = new OutputStreamWriter(outputStream, StandardCharsets.UTF_8);
		try {
			root.write(writer);
		} finally {
			IoUtils.ensureClose(writer);
		}
	}

}
