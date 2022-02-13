package com.logpresso.scanner.utils;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;

public class IoUtils {
	public static File getJarDir() {
		try {
			File jarPath = new File(
					URLDecoder.decode(IoUtils.class.getProtectionDomain().getCodeSource().getLocation().getPath(), "utf-8"));
			return jarPath.getParentFile();
		} catch (UnsupportedEncodingException e) {
			// unreachable
			throw new IllegalStateException(e);
		}
	}

	public static String getHostname(boolean debug) {
		// Try to fetch hostname without DNS resolving for closed network
		boolean isWindows = File.separatorChar == '\\';
		if (isWindows) {
			return System.getenv("COMPUTERNAME");
		} else {
			Process p = null;
			try {
				p = Runtime.getRuntime().exec("uname -n");
				BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));

				String line = br.readLine();
				return (line == null) ? null : line.trim();
			} catch (IOException e) {
				if (debug)
					e.printStackTrace();

				return null;
			} finally {
				if (p != null)
					p.destroy();
			}
		}
	}

	public static List<String> loadLines(File f) throws IOException {
		List<String> lines = new ArrayList<String>();
		FileInputStream fis = null;
		BufferedReader br = null;
		try {
			br = new BufferedReader(new InputStreamReader(new FileInputStream(f), "utf-8"));

			while (true) {
				String line = br.readLine();
				if (line == null)
					break;

				line = line.trim();

				if (line.startsWith("#") || line.isEmpty())
					continue;

				lines.add(line);
			}

			return lines;
		} finally {
			IoUtils.ensureClose(fis);
			IoUtils.ensureClose(br);
		}

	}

	public static void ensureClose(Closeable c) {
		if (c != null) {
			try {
				c.close();
			} catch (Throwable t) {
			}
		}
	}
}
