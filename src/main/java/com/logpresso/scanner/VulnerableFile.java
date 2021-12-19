package com.logpresso.scanner;

import java.io.File;
import java.nio.charset.Charset;

public class VulnerableFile implements Comparable<VulnerableFile> {
	private File file;
	private boolean nestedJar;
	private Charset altCharset;

	public VulnerableFile(File file, boolean nestedJar, Charset altCharset) {
		if (file == null)
			throw new IllegalArgumentException("file should be not null");

		this.file = file;
		this.nestedJar = nestedJar;
		this.altCharset = altCharset;
	}

	@Override
	public int hashCode() {
		return file == null ? 0 : file.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		VulnerableFile other = (VulnerableFile) obj;
		if (file == null) {
			if (other.file != null)
				return false;
		} else if (!file.equals(other.file))
			return false;
		return true;
	}

	public int compareTo(VulnerableFile o) {
		return file.compareTo(o.file);
	}

	public File getFile() {
		return file;
	}

	public boolean isNestedJar() {
		return nestedJar;
	}

	public Charset getAltCharset() {
		return altCharset;
	}
}
