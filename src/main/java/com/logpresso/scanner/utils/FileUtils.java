package com.logpresso.scanner.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.lang.reflect.Method;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;

public class FileUtils {
	private FileUtils() {
	}

	// use JDK7 feature
	public static boolean isSymlink(File f) {
		Path path = f.toPath();
		boolean isWindows = File.separatorChar == '\\';
		if (isWindows) {
			try {
				BasicFileAttributes attr = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
				if (DosFileAttributes.class.isInstance(attr)) {
					Method m = attr.getClass().getDeclaredMethod("isReparsePoint");
					m.setAccessible(true);
					boolean isReparsePoint = (Boolean) m.invoke(attr);
					if (isReparsePoint)
						return true;
				}
			} catch (Exception e) {
			}
		}

		return Files.isSymbolicLink(f.toPath());
	}

	public static void checkLock(File f) throws IOException {
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(f, "rw");
			FileLock lock = raf.getChannel().lock();
			lock.release();
		} finally {
			IoUtils.ensureClose(raf);
		}
	}

	public static void truncate(File f) throws IOException {
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(f, "rw");
			raf.setLength(0);
		} catch (Throwable t) {
			throw new IOException("Cannot truncate file - " + t.getMessage(), t);
		} finally {
			IoUtils.ensureClose(raf);
		}
	}

	public static int readMagic(File f) throws IOException {
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(f, "r");
			return raf.readInt();
		} finally {
			IoUtils.ensureClose(raf);
		}
	}

	public static void copyAsIs(File srcFile, File dstFile) throws IOException {
		FileInputStream is = null;
		FileOutputStream os = null;

		try {
			is = new FileInputStream(srcFile);
			os = new FileOutputStream(dstFile);
			transfer(is, os);
		} finally {
			IoUtils.ensureClose(is);
			IoUtils.ensureClose(os);
		}
	}

	public static long transfer(InputStream is, OutputStream os) throws IOException {
		long total = 0;
		byte[] buf = new byte[32768];
		while (true) {
			int len = is.read(buf);
			if (len < 0)
				break;

			os.write(buf, 0, len);
			total += len;
		}

		return total;
	}

	public static String readLine(File f) throws IOException {
		BufferedReader br = null;
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(f);
			br = new BufferedReader(new InputStreamReader(fis, "utf-8"));
			return br.readLine();
		} finally {
			IoUtils.ensureClose(br);
		}
	}

	public static void writeLine(File f, String line) throws IOException {
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(f);
			fos.write(line.getBytes("utf-8"));
		} finally {
			IoUtils.ensureClose(fos);
		}
	}
}
