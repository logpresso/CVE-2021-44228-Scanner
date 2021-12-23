package com.logpresso.scanner.utils;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;

public class ZipFileIterator implements Closeable {

	private ZipFile zipFile;
	private ZipInputStream zis;
	private ZipArchiveInputStream commonsZis;
	private Enumeration<? extends ZipEntry> e;

	private ZipEntry firstEntry;
	private ZipEntry nextEntry;

	public ZipFileIterator(File file, Charset charset) throws IOException {
		this.zipFile = new ZipFile(file, charset);
		e = zipFile.entries();
		if (e.hasMoreElements()) {
			firstEntry = e.nextElement();
			nextEntry = firstEntry;
		}
	}

	public ZipFileIterator(ZipInputStream zis) throws IOException {
		this.zis = zis;
		firstEntry = zis.getNextEntry();
	}

	public ZipFileIterator(ZipArchiveInputStream zis) throws IOException {
		this.commonsZis = zis;
		firstEntry = zis.getNextZipEntry();
	}

	public ZipEntry getNextEntry() throws IOException {
		if (firstEntry != null) {
			ZipEntry e = firstEntry;
			firstEntry = null;
			return e;
		}

		if (zipFile != null) {
			if (e.hasMoreElements()) {
				this.nextEntry = e.nextElement();
				return nextEntry;
			} else {
				return null;
			}
		} else if (zis != null) {
			this.nextEntry = zis.getNextEntry();
			return nextEntry;
		} else {
			this.nextEntry = commonsZis.getNextZipEntry();
			return nextEntry;
		}
	}

	public InputStream getNextInputStream() throws IOException {
		if (zipFile != null)
			return zipFile.getInputStream(nextEntry);
		else if (zis != null)
			return zis;
		return commonsZis;
	}

	public void close() throws IOException {
		if (zipFile != null)
			zipFile.close();

		if (commonsZis != null)
			IoUtils.ensureClose(commonsZis);
	}

}
