package com.logpresso.scanner;

import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.util.Date;

import com.logpresso.scanner.json.JsonObject;
import com.logpresso.scanner.utils.IoUtils;

public class LogGenerator implements LogListener, Closeable {

	private static final String LF = File.separatorChar == '\\' ? "\r\n" : "\n";
	private static final boolean APPEND = true;
	private static final byte[] BOM = new byte[] { (byte) 0xEF, (byte) 0xBB, (byte) 0xBF };

	// See rfc5424
	private static final int SEVERITY_ALERT = 1;
	private static final int SEVERITY_WARN = 4;
	private static final int SEVERITY_NOTICE = 5;

	public final String priAlert;
	public final String priWarn;
	public final String priNotice;

	private Configuration config;
	private String hostname;
	private DatagramSocket socket;
	private FileOutputStream csvFileOutput;
	private FileOutputStream jsonFileOutput;

	public LogGenerator(Configuration config) throws IOException {
		this.config = config;
		this.hostname = IoUtils.getHostname(config.isDebug());

		if (config.getUdpSyslogAddr() != null)
			socket = new DatagramSocket();

		if (config.getCsvLogPath() != null) {
			boolean addHeader = !config.getCsvLogPath().exists();
			csvFileOutput = new FileOutputStream(config.getCsvLogPath(), APPEND);
			if (addHeader) {
				String header = String
						.format("\"Hostname\",\"Path\",\"Entry\",\"Product\",\"Version\",\"CVE\",\"Status\",\"Fixed\",\"Detected at\"%n");
				csvFileOutput.write(header.getBytes("utf-8"));
				csvFileOutput.flush();
			}
		}

		if (config.getJsonLogPath() != null)
			jsonFileOutput = new FileOutputStream(config.getJsonLogPath(), APPEND);

		priAlert = String.format("<%d>", config.getSyslogFacility() * 8 + SEVERITY_ALERT);
		priWarn = String.format("<%d>", config.getSyslogFacility() * 8 + SEVERITY_WARN);
		priNotice = String.format("<%d>", config.getSyslogFacility() * 8 + SEVERITY_NOTICE);
	}

	@Override
	public void close() throws IOException {
		IoUtils.ensureClose(socket);
		IoUtils.ensureClose(csvFileOutput);
		IoUtils.ensureClose(jsonFileOutput);
	}

	@Override
	public void onDetect(ReportEntry entry) {
		if (socket != null)
			sendDetectSyslog(entry);

		if (csvFileOutput != null)
			writeDetectCsvLog(entry);

		if (jsonFileOutput != null)
			writeDetectJsonLog(entry);
	}

	@Override
	public void onError(ReportEntry entry) {
		if (socket != null)
			sendErrorSyslog(entry);

		if (jsonFileOutput != null)
			writeErrorJsonLog(entry);
	}

	private String getErrorLog(ReportEntry entry) {
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");
		String escapedPath = JsonObject.escape(entry.getPath().getAbsolutePath());
		String escapedError = entry.getError() != null ? JsonObject.escape(entry.getError()) : "";
		return String.format("{\"time\": \"%s\", \"hostname\": \"%s\", \"path\": \"%s\", \"error\": \"%s\"}",
				df.format(entry.getReportTime()), hostname, escapedPath, escapedError);
	}

	private void writeDetectCsvLog(ReportEntry entry) {
		String log = entry.getCsvLine(hostname);
		writeFile(log, csvFileOutput);
	}

	private void writeDetectJsonLog(ReportEntry entry) {
		String log = entry.getJsonLine(hostname) + LF;
		writeFile(log, jsonFileOutput);
	}

	private void writeErrorJsonLog(ReportEntry entry) {
		String log = getErrorLog(entry) + LF;
		writeFile(log, jsonFileOutput);
	}

	private void writeFile(String line, FileOutputStream fos) {
		try {
			fos.write(line.getBytes("utf-8"));

			// for incremental loading
			fos.flush();
		} catch (Throwable t) {
			System.out.println("Error: Cannot write log file (" + t.getMessage() + ")");
			if (config.isDebug())
				t.printStackTrace();
		}

	}

	private void sendDetectSyslog(ReportEntry entry) {
		try {
			String msg = entry.getJsonLine(hostname);
			byte[] syslog = null;
			if (entry.getStatus() == Status.VULNERABLE)
				syslog = formatSyslog(priAlert, "DETECT", msg);
			else if (entry.getStatus() == Status.POTENTIALLY_VULNERABLE)
				syslog = formatSyslog(priWarn, "DETECT", msg);
			else if (entry.getStatus() == Status.MITIGATED && config.getSyslogLevel().ordinal() <= SyslogLevel.INFO.ordinal())
				syslog = formatSyslog(priNotice, "DETECT", msg);
			else
				return;

			sendSyslogPacket(socket, config.getUdpSyslogAddr(), syslog);

		} catch (Throwable t) {
			System.out.println("Error: Cannot send syslog to " + config.getUdpSyslogAddr() + " - " + t.getMessage());
			if (config.isDebug())
				t.printStackTrace();
		}
	}

	private void sendErrorSyslog(ReportEntry entry) {
		if (config.getSyslogLevel() != SyslogLevel.DEBUG)
			return;

		try {
			String msg = getErrorLog(entry);
			byte[] syslog = formatSyslog("<135>", "ERROR", msg);
			sendSyslogPacket(socket, config.getUdpSyslogAddr(), syslog);
		} catch (Throwable t) {
			System.out.println("Error: Cannot send syslog to " + config.getUdpSyslogAddr() + " - " + t.getMessage());
			if (config.isDebug())
				t.printStackTrace();
		}
	}

	private byte[] formatSyslog(String pri, String msgId, String msg) throws UnsupportedEncodingException {
		if (config.isRfc5424()) {
			// https://datatracker.ietf.org/doc/html/rfc5424#section-6
			// PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP
			// STRUCTURED-DATA SP MSG
			SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
			String timestamp = df.format(new Date());

			byte[] header = String.format("%s1 %s %s LOGPRESSO LOG4J2-SCAN %s - ", pri, timestamp, hostname, msgId)
					.getBytes("utf-8");
			byte[] body = msg.getBytes("utf-8");

			byte[] syslog = new byte[header.length + 3 + body.length];
			ByteBuffer bb = ByteBuffer.wrap(syslog);
			bb.put(header);
			bb.put(BOM);
			bb.put(body);

			return syslog;
		} else {
			return (pri + msg).getBytes("utf-8");
		}
	}

	private void sendSyslogPacket(DatagramSocket socket, InetSocketAddress remote, byte[] syslog) throws IOException {
		DatagramPacket pkt = new DatagramPacket(syslog, syslog.length);
		pkt.setSocketAddress(remote);
		socket.send(pkt);
	}
}
