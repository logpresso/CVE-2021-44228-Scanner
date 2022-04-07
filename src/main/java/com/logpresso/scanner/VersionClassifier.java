package com.logpresso.scanner;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.logpresso.scanner.utils.IoUtils;

public class VersionClassifier {
	private static final char[] HEX_CODES = "0123456789abcdef".toCharArray();
	private static final Map<String, String> log4j1Digests;

	private static final Map<String, String> log4j2RollingFileManagerDigests;
	private static final Map<String, String> log4j2AppenderControlDigests;
	private static final Map<String, String> log4j2LoggerConfigDigests;
	private static final Map<String, String> log4j2ThreadContextMapDigests;
	private static final Map<String, String> log4j2OutputStreamManagerDigests;
	private static final Map<String, String> log4j2AsyncLoggerDigests;
	private static final Map<String, String> log4j2AsyncAppenderDigests;
	private static final Map<String, String> log4j2InterpolatorDigests;
	private static final Map<String, String> jndiManagerDigests;

	static {
		log4j1Digests = new HashMap<String, String>();
		log4j1Digests.put("906c9e0fd306e8b499b7f2dc84e2fef3", "1.1.3");
		log4j1Digests.put("37fa11f47f3b8d40882f8ee61b06e69f", "1.2.4");
		log4j1Digests.put("3f2f6a1ac893cb01c8f749036a1be514", "1.2.8");
		log4j1Digests.put("caea0074e17f5f84ee60804781f2f2a0", "1.2.9");
		log4j1Digests.put("d0b058288138bda4fccb504d4046e08c", "1.2.11");
		log4j1Digests.put("6bac921015bb8300d36df01d0bf1ceb4", "1.2.12");
		log4j1Digests.put("ff67193faa9007c0afc57dbc04c983bb", "1.2.15");
		log4j1Digests.put("bd5186a7747acdd133105873fbfefdb1", "1.2.16");
		log4j1Digests.put("e8dedc13853f852f1af6900d2d9c73b3", "1.2.17");
		log4j1Digests.put("1bd049612eaddf4fe8a8bc3cb2179dbf", "1.2.17"); // with generics

		log4j2RollingFileManagerDigests = new HashMap<String, String>();
		log4j2RollingFileManagerDigests.put("66c1b131a623bd368e6d8bebbe16ff0c", "2.0-alpha1");
		log4j2RollingFileManagerDigests.put("ea91f7e905890c4748a97e09937d3b87", "2.0-alpha2");
		log4j2RollingFileManagerDigests.put("d09d7e21eea3985436167edc8bb8683b", "2.0-beta1");
		log4j2RollingFileManagerDigests.put("7353cce6841e400fd840887cba14d55d", "2.0-beta2");
		log4j2RollingFileManagerDigests.put("3e3f74e5af5d0b22a5e38b877f500711", "2.0-beta3");
		log4j2RollingFileManagerDigests.put("167dfbf8e4da0fccc1145f841ac3d035", "2.0-beta4");
		log4j2RollingFileManagerDigests.put("d02e41ca06e35a28dbda2e8721142a72", "2.0-beta9");
		log4j2RollingFileManagerDigests.put("8e8beef8634c0aff2e5d63fcc87c6661", "2.0-rc1");
		log4j2RollingFileManagerDigests.put("7918c364db8a499eda4408bb9529fb0e", "2.0-rc2");
		log4j2RollingFileManagerDigests.put("48ecb3c6a378c045482aa4ba3bd1afe5", "2.3");
		log4j2RollingFileManagerDigests.put("fd9d433dc83d1aaf88548e713693d8e2", "2.3.1");
		log4j2RollingFileManagerDigests.put("5e156e9b4ae0e291c0987d9caf3a3f5a", "2.3.2");
		log4j2RollingFileManagerDigests.put("39db3f6132358787af20766bba757574", "2.4");
		log4j2RollingFileManagerDigests.put("a2b1489d08fe47392db0267f42e96938", "2.4.1");
		log4j2RollingFileManagerDigests.put("031c3ae10ee8fd24a9fa00366cc1e010", "2.5");
		log4j2RollingFileManagerDigests.put("1580aa3de80d9ac181c2ae78b1eb777f", "2.6.2");
		log4j2RollingFileManagerDigests.put("7027c29e04281037abfd22ef0b16c3af", "2.7");
		log4j2RollingFileManagerDigests.put("63939a357e427fadb975287084d3dd0f", "2.8");
		log4j2RollingFileManagerDigests.put("46b9a7341456824e15d9d6ad71323039", "2.8.1");
		log4j2RollingFileManagerDigests.put("50ca27cb0b2cf02cc5ef97d3401d4fb5", "2.8.2");
		log4j2RollingFileManagerDigests.put("7dc1c465224f386d404574d76432583c", "2.11.1");
		log4j2RollingFileManagerDigests.put("4206094f030c94db57d75ec11b17b606", "2.11.2");
		log4j2RollingFileManagerDigests.put("dc95679162dde24806281fce2609d84f", "2.12.3");
		log4j2RollingFileManagerDigests.put("d71ec841dcaaa158adda0c326b8b30eb", "2.13.0");
		log4j2RollingFileManagerDigests.put("4bef436fd4aadff166f3ccf49e920208", "2.13.1");
		log4j2RollingFileManagerDigests.put("dd1fd2b1c1bbe6f7543e6fb6c2fd8a78", "2.14.0");
		log4j2RollingFileManagerDigests.put("81b374404981e7739e514de150b16416", "2.14.1");

		log4j2AppenderControlDigests = new HashMap<String, String>();
		log4j2AppenderControlDigests.put("f2b2d44ebdb80db7d87e7d44e050f689", "2.12.4");
		log4j2AppenderControlDigests.put("445b65145d2e9ccbdcd0238e20acc15a", "2.15.0");
		log4j2AppenderControlDigests.put("c41c4e77e28a414e9512e889fe72c26e", "2.16.0");
		log4j2AppenderControlDigests.put("e7cd10930f7efcf09c43fd580f476491", "2.17.0");
		log4j2AppenderControlDigests.put("b1e72c1608d69230e852de53f411553c", "2.17.1");

		log4j2LoggerConfigDigests = new HashMap<String, String>();
		log4j2LoggerConfigDigests.put("17ad30e070723548423f8b01f892cea5", "2.0-beta5");
		log4j2LoggerConfigDigests.put("5d6696388448e169cd29ee5426187bc5", "2.0-beta6");
		log4j2LoggerConfigDigests.put("8353ff994104395cedf609330b0c13ed", "2.0-beta7");
		log4j2LoggerConfigDigests.put("fd9c4cbc794aa8cc56e261f7f193ff17", "2.0-beta8");
		log4j2LoggerConfigDigests.put("a73f488fd9770a6ba44b1944e879622d", "2.12.0");
		log4j2LoggerConfigDigests.put("54da0558628cfabae6eeeabf9d284f8e", "2.12.1");

		log4j2ThreadContextMapDigests = new HashMap<String, String>();
		log4j2ThreadContextMapDigests.put("9d7a8b73a4c83493703805bcaa97d5f4", "2.13.2");
		log4j2ThreadContextMapDigests.put("687baf0490162fc956f6365c7894ab1a", "2.13.3");

		log4j2AsyncAppenderDigests = new HashMap<String, String>();
		log4j2AsyncAppenderDigests.put("744dc79c1ce978a5ce6aee7acc63e7de", "2.10.0");
		log4j2AsyncAppenderDigests.put("08ce0e2441b7a51a887489494da447ad", "2.11.0");

		log4j2AsyncLoggerDigests = new HashMap<String, String>();
		log4j2AsyncLoggerDigests.put("f1b4a01e8163a752e4bd969433d70481", "2.9.0");
		log4j2AsyncLoggerDigests.put("10a184fde310fb171cd668b39a8f63fb", "2.9.1");

		log4j2OutputStreamManagerDigests = new HashMap<String, String>();
		log4j2OutputStreamManagerDigests.put("0d67bfd717ee9cc3b5b35d5083e6d01a", "2.6");
		log4j2OutputStreamManagerDigests.put("c46438987ce8df640eab163bb20a3d83", "2.6.1");

		log4j2InterpolatorDigests = new HashMap<String, String>();
		log4j2InterpolatorDigests.put("763b4af13fd37d076122b2c9aff02790", "2.12.2");

		// known shaded md5 hashes
		jndiManagerDigests = new HashMap<String, String>();

		// https://download.newrelic.com/newrelic/java-agent/newrelic-agent/current/newrelic.jar
		jndiManagerDigests.put("e2c6b2691738bb653f1ff6dc4b967a42", "2.17.1");
	}

	public static List<String> getLog4j1Md5Entries() {
		return Arrays.asList("/log4j/Category.class", "/log4j/MDC.class", "/log4j/NDC.class", "/log4j/net/JMSSink.class",
				"/log4j/helpers/PatternParser.class", "/log4j/net/SMTPAppender.class");
	}

	public static List<String> getLog4j2Md5Entries() {
		return Arrays.asList("/log4j/core/appender/rolling/RollingFileManager.class", "/log4j/core/config/LoggerConfig.class",
				"/log4j/core/appender/AsyncAppender.class", "/log4j/core/lookup/Interpolator.class",
				"/log4j/core/config/AppenderControl.class",
				"/log4j/core/impl/ThreadContextDataInjector$ForCopyOnWriteThreadContextMap.class",
				"/log4j/core/appender/OutputStreamManager.class", "/log4j/core/async/AsyncLogger.class",
				"/log4j/core/net/JndiManager.class");
	}

	@SuppressWarnings("unchecked")
	public static String classifyLog4j2Version(Map<String, String> entryMd5Map) {

		final String[] classFileNames = new String[] { "RollingFileManager.class", "LoggerConfig.class", "AppenderControl.class",
				"ThreadContextDataInjector$ForCopyOnWriteThreadContextMap.class", "AsyncAppender.class",
				"OutputStreamManager.class", "AsyncLogger.class", "Interpolator.class", "JndiManager.class" };

		final Map<String, String>[] digestMaps = new Map[] { log4j2RollingFileManagerDigests, log4j2LoggerConfigDigests,
				log4j2AppenderControlDigests, log4j2ThreadContextMapDigests, log4j2AsyncAppenderDigests,
				log4j2OutputStreamManagerDigests, log4j2AsyncLoggerDigests, log4j2InterpolatorDigests, jndiManagerDigests };

		for (int i = 0; i < classFileNames.length; i++) {
			String version = detectLog4j2Version(classFileNames[i], entryMd5Map, digestMaps[i]);
			if (version != null)
				return version;
		}

		return null;
	}

	private static String detectLog4j2Version(String classFileName, Map<String, String> entryMd5Map,
			Map<String, String> digests) {
		String md5 = entryMd5Map.get(classFileName);
		if (md5 == null)
			return null;

		return digests.get(md5);
	}

	public static String classifyLog4j1Version(Map<String, String> entryMd5Map) {
		String categoryMd5 = entryMd5Map.get("Category.class");
		String ndcMd5 = entryMd5Map.get("NDC.class");
		String mdcMd5 = entryMd5Map.get("MDC.class");
		String jmsSinkMd5 = entryMd5Map.get("JMSSink.class");
		String patternParserMd5 = entryMd5Map.get("PatternParser.class");
		String smtpAppenderMd5 = entryMd5Map.get("SMTPAppender.class");

		if (categoryMd5 == null)
			return null;

		if (categoryMd5.equals("f1dda8732d825c58248e4c85f6bfff80")) {
			if (ndcMd5 == null)
				return null;

			if (ndcMd5.equals("1d79e7ecd65f4ec0560420024a8086f2"))
				return "1.2.13";
			else if (ndcMd5.equals("b5223239f2810943933b54d8ea681763"))
				return "1.2.14";
		} else if (categoryMd5.equals("ffbeb79ef0d29a902b84c8c06cac91ae")) {
			if (mdcMd5 == null)
				return null;

			if (mdcMd5.equals("cc556397bdabc4995892b18d2e6246f0")) {
				return "1.2.5";
			} else if (mdcMd5.equals("f74d8a96370d7776331dde8718a12990")) {
				return "1.2.6";
			} else if (mdcMd5.equals("8543bd826940dd588cd63b1118a82e90")) {
				return "1.2.7";
			}
		} else {
			if (jmsSinkMd5 != null && jmsSinkMd5.equals("016dbb16c0d5509c13dad7b483b4e648")) {
				return "1.2.18.0";
			} else if (smtpAppenderMd5 != null && smtpAppenderMd5.equals("3bff44742e88190fa9f200826af64d9c")) {
				return "1.2.18.3";
			} else if (smtpAppenderMd5 != null && smtpAppenderMd5.equals("7f938ce7dc9df0389d38d3ca40296015")) {
				return "1.2.18.4";
			} else if (mdcMd5 != null && mdcMd5.equals("8da7e55001d400655635bbbbc3381ba5")) {
				if (patternParserMd5 != null && patternParserMd5.equals("619e0839a36f541a49016e42c99db710")) {
					return "1.2.18.1";
				} else if (patternParserMd5 != null && patternParserMd5.equals("4848724cd715a2e855d1413a1e15c7c3")) {
					return "1.2.18.2";
				} else {
					return log4j1Digests.get(categoryMd5);
				}
			} else if (mdcMd5 != null && mdcMd5.equals("4bb635421ade486060d68134de4ac74e")) {
				return "1.2.19";
			}

			return log4j1Digests.get(categoryMd5);
		}

		return null;
	}

	public static Map<String, String> generateSignature(File f) {
		Map<String, String> digests = new LinkedHashMap<String, String>();
		ZipInputStream zis = null;
		ZipEntry entry = null;
		try {
			zis = new ZipInputStream(new FileInputStream(f));
			while (true) {
				entry = zis.getNextEntry();
				if (entry == null)
					break;

				if (entry.getName().endsWith("/"))
					continue;

				String md5 = md5(zis);
				digests.put(entry.getName(), md5);
			}
			return digests;
		} catch (IOException e) {
			throw new IllegalStateException("cannot load zip entry " + entry, e);
		} finally {
			IoUtils.ensureClose(zis);
		}
	}

	public static String md5(InputStream is) {
		try {
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			byte[] b = new byte[8192];
			while (true) {
				int len = is.read(b);
				if (len < 0)
					break;
				md5.update(b, 0, len);
			}

			return toHex(md5.digest());
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("md5 is not supported");
		} catch (IOException e) {
			throw new IllegalStateException("md5 error", e);
		}
	}

	private static String toHex(byte[] data) {
		char[] hex = new char[data.length * 2];
		for (int i = 0; i < data.length; i++) {
			hex[i * 2] = HEX_CODES[(data[i] >> 4) & 0xF];
			hex[i * 2 + 1] = HEX_CODES[data[i] & 0xF];
		}
		return new String(hex);
	}

	public static void main(String[] args) throws IOException {
		File[] files = new File(args[0]).listFiles();
		for (File f : files) {
			if (f.getName().endsWith(".sig"))
				continue;

			FileOutputStream fos = null;
			try {
				fos = new FileOutputStream(new File(f.getAbsolutePath() + ".sig"));
				Map<String, String> signatures = generateSignature(f);
				System.out.println(f.getAbsolutePath());

				for (String name : signatures.keySet()) {
					String md5 = signatures.get(name);
					String line = md5 + " " + name + "\n";
					System.out.print(line);

					fos.write(line.getBytes("utf-8"));
				}

				System.out.println("---");
			} finally {
				IoUtils.ensureClose(fos);
			}
		}
	}
}
