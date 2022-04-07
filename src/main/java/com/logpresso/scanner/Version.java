package com.logpresso.scanner;

public class Version {
	private int major;
	private int minor;
	private int patch;
	private int patch2;

	public static Version parse(String version) {
		String ver = version;
		int p = version.indexOf('-');
		if (p > 0)
			ver = version.substring(0, p);

		String[] tokens = ver.split("\\.");
		int major = Integer.parseInt(tokens[0]);
		int minor = Integer.parseInt(tokens[1]);
		int patch = 0;
		int patch2 = 0;

		// e.g. version 2.0 has only 2 tokens
		if (tokens.length > 2)
			patch = Integer.parseInt(tokens[2]);

		// added for reload4j version scheme
		if (tokens.length > 3)
			patch2 = Integer.parseInt(tokens[3]);

		return new Version(major, minor, patch, patch2);
	}

	public Version(int major, int minor, int patch, int patch2) {
		this.major = major;
		this.minor = minor;
		this.patch = patch;
		this.patch2 = patch2;
	}

	public int getMajor() {
		return major;
	}

	public int getMinor() {
		return minor;
	}

	public int getPatch() {
		return patch;
	}

	public int getPatch2() {
		return patch2;
	}
}
