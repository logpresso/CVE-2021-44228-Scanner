package com.logpresso.scanner.utils;

import java.io.IOException;
import java.io.InputStream;

// don't close underlying InputStream on close
public class DummyInputStream extends InputStream {

	private InputStream is;

	public DummyInputStream(InputStream is) {
		this.is = is;
	}

	@Override
	public int read() throws IOException {
		return is.read();
	}

	@Override
	public int read(byte[] b) throws IOException {
		return is.read(b);
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		return is.read(b, off, len);
	}

	@Override
	public long skip(long n) throws IOException {
		return is.skip(n);
	}

	@Override
	public int available() throws IOException {
		return is.available();
	}

	@Override
	public void close() throws IOException {
		// ignore intentionally
	}

	@Override
	public synchronized void mark(int readlimit) {
		is.mark(readlimit);
	}

	@Override
	public synchronized void reset() throws IOException {
		is.reset();
	}

	@Override
	public boolean markSupported() {
		return is.markSupported();
	}

	@Override
	public int hashCode() {
		return is.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		return is.equals(obj);
	}

	@Override
	public String toString() {
		return is.toString();
	}
}
