package com.logpresso.scanner;

public interface LogListener {
	void onDetect(ReportEntry entry);

	void onError(ReportEntry entry);
}
