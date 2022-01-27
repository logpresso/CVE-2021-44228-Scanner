package com.logpresso.scanner;

import java.io.File;

public class Metrics {
	// status logging
	private long scanStartTime = 0;
	private long lastStatusLoggingTime = System.currentTimeMillis();
	private long lastStatusLoggingCount = 0;
	private File lastVisitDirectory = null;

	// results
	private long scanDirCount = 0;
	private long scanFileCount = 0;
	private int fixedFileCount = 0;
	private int errorCount = 0;

	// speed control
	private int throttle;
	private int fileCounter;
	private long lastResetTime;

	public Metrics(int throttle) {
		this.throttle = throttle;
		this.lastResetTime = System.currentTimeMillis();
	}

	public boolean canStatusReporting() {
		// check scan file count to reduce system call overhead
		return scanFileCount - lastStatusLoggingCount >= 1000 && System.currentTimeMillis() - lastStatusLoggingTime >= 10000;
	}

	public void setLastStatusLogging() {
		this.lastStatusLoggingCount = scanFileCount;
		this.lastStatusLoggingTime = System.currentTimeMillis();
	}

	public long getScanStartTime() {
		return scanStartTime;
	}

	public void setScanStartTime(long scanStartTime) {
		this.scanStartTime = scanStartTime;
	}

	public long getLastStatusLoggingTime() {
		return lastStatusLoggingTime;
	}

	public long getLastStatusLoggingCount() {
		return lastStatusLoggingCount;
	}

	public File getLastVisitDirectory() {
		return lastVisitDirectory;
	}

	public long getScanDirCount() {
		return scanDirCount;
	}

	public long getScanFileCount() {
		return scanFileCount;
	}

	public int getFixedFileCount() {
		return fixedFileCount;
	}

	public int getErrorCount() {
		return errorCount;
	}

	public void addScanFileCount() {
		scanFileCount++;
		fileCounter++;

		if (throttle == 0)
			return;

		if (throttle <= fileCounter) {
			while (true) {
				long elapsed = System.currentTimeMillis() - lastResetTime;
				if (elapsed >= 1000) {
					break;
				}

				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
				}
			}

			lastResetTime = System.currentTimeMillis();
			fileCounter = 0;
		}

	}

	public void addScanDirCount() {
		scanDirCount++;
	}

	public void addErrorCount() {
		errorCount++;
	}

	public void addFixedFileCount() {
		fixedFileCount++;
	}

	public void setLastVisitDirectory(File dir) {
		this.lastVisitDirectory = dir;
	}

}
