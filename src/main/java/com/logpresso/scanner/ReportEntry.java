package com.logpresso.scanner;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

import com.logpresso.scanner.json.JsonObject;

public class ReportEntry {
	private File path;
	private String entry;
	private String product;
	private String version;
	private String cve;
	private Status status;
	private boolean fixed;
	private String error;
	private Date reportTime = new Date();

	public ReportEntry(File path, String error) {
		this.path = path;
		this.status = Status.ERROR;
		this.error = error;
	}

	public ReportEntry(File path, String entry, String product, String version) {
		this(path, entry, product, version, null, Status.NOT_VULNERABLE);
	}

	public ReportEntry(File path, String entry, String product, String version, String cve, Status status) {
		this.path = path;
		this.entry = entry;
		this.product = product;
		this.version = version;
		this.cve = cve;
		this.status = status;
	}

	public File getPath() {
		return path;
	}

	public String getEntry() {
		return entry;
	}

	public String getProduct() {
		return product;
	}

	public void setProduct(String product) {
		this.product = product;
	}

	public String getVersion() {
		return version;
	}

	public String getCve() {
		return cve;
	}

	public Status getStatus() {
		return status;
	}

	public boolean isFixed() {
		return fixed;
	}

	public void setFixed(boolean fixed) {
		this.fixed = fixed;
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

	public Date getReportTime() {
		return reportTime;
	}

	public String getJsonLine(String hostname) {
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");
		String escapedPath = JsonObject.escape(path.getAbsolutePath());
		String escapedEntry = JsonObject.escape(entry);
		return String.format("{\"time\": \"%s\", \"hostname\": \"%s\", \"path\": \"%s\", "
				+ "\"entry\": \"%s\", \"product\": \"%s\", \"version\": \"%s\", \"cve\": \"%s\", \"status\": \"%s\", \"fixed\": %s}",
				df.format(reportTime), hostname, escapedPath, escapedEntry, product, version, cve, status, fixed);
	}

	public String getCsvLine(String hostname) {
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		return String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n", hostname, path.getAbsolutePath(),
				entry, product, version, cve, status, fixed ? "FIXED" : "", df.format(reportTime));
	}
}
